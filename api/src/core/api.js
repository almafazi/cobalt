import cors from "cors";
import http from "node:http";
import rateLimit from "express-rate-limit";
import { setGlobalDispatcher, ProxyAgent } from "undici";
import { getCommit, getBranch, getRemote, getVersion } from "@imput/version-info";

import jwt from "../security/jwt.js";
import stream from "../stream/stream.js";
import match from "../processing/match.js";
import path from 'path';

import { env, isCluster, setTunnelPort } from "../config.js";
import { extract } from "../processing/url.js";
import { Green, Bright, Cyan } from "../misc/console-text.js";
import { hashHmac } from "../security/secrets.js";
import { createStore } from "../store/redis-ratelimit.js";
import { decrypt } from "../misc/crypto.js";
import { randomizeCiphers } from "../misc/randomize-ciphers.js";
import { verifyTurnstileToken } from "../security/turnstile.js";
import { friendlyServiceName } from "../processing/service-alias.js";
import { verifyStream, getInternalStream } from "../stream/manage.js";
import { createResponse, normalizeRequest, getIP } from "../processing/request.js";
import youtubesearchapi from 'youtube-search-api';
import NodeCache from "node-cache";
import * as APIKeys from "../security/api-keys.js";
import processRequest from "../processing/render-video.js";
import fs from 'fs'; // Import fs

// import { createClient } from 'redis';
// const redisClient = createClient();
// await redisClient.connect();
import * as Cookies from "../processing/cookie/manager.js";
import got from "got";

const git = {
    branch: await getBranch(),
    commit: await getCommit(),
    remote: await getRemote(),
}

const version = await getVersion();

const cache = new NodeCache({ stdTTL: 432000 });

const acceptRegex = /^application\/json(; charset=utf-8)?$/;

const corsConfig = env.corsWildcard ? {} : {
    origin: env.corsURL,
    optionsSuccessStatus: 200
}

const fail = (res, code, context) => {
    const { status, body } = createResponse("error", { code, context });
    res.status(status).json(body);
}

export const runAPI = async (express, app, __dirname, isPrimary = true) => {
    const startTime = new Date();
    const startTimestamp = startTime.getTime();

    const serverInfo = JSON.stringify({
        cobalt: {
            version: version,
            url: env.apiURL,
            startTime: `${startTimestamp}`,
            durationLimit: env.durationLimit,
            turnstileSitekey: env.sessionEnabled ? env.turnstileSitekey : undefined,
            services: [...env.enabledServices].map(e => {
                return friendlyServiceName(e);
            }),
        },
        git,
    })

    const handleRateExceeded = (_, res) => {
        const { status, body } = createResponse("error", {
            code: "error.api.rate_exceeded",
            context: {
                limit: env.rateLimitWindow
            }
        });
        return res.status(status).json(body);
    };

    const keyGenerator = (req) => hashHmac(getIP(req), 'rate').toString('base64url');

    const sessionLimiter = rateLimit({
        windowMs: 60000,
        limit: 10,
        standardHeaders: 'draft-6',
        legacyHeaders: false,
        keyGenerator,
        store: await createStore('session'),
        handler: handleRateExceeded
    });

    const apiLimiter = rateLimit({
        windowMs: env.rateLimitWindow * 1000,
        limit: (req) => req.rateLimitMax || env.rateLimitMax,
        standardHeaders: 'draft-6',
        legacyHeaders: false,
        keyGenerator: req => req.rateLimitKey || keyGenerator(req),
        store: await createStore('api'),
        handler: handleRateExceeded
    })

    const apiTunnelLimiter = rateLimit({
        windowMs: env.rateLimitWindow * 1000,
        limit: (req) => req.rateLimitMax || env.rateLimitMax,
        standardHeaders: 'draft-6',
        legacyHeaders: false,
        keyGenerator: req => req.rateLimitKey || keyGenerator(req),
        store: await createStore('tunnel'),
        handler: (_, res) => {
            return res.sendStatus(429)
        }
    })

    app.set('trust proxy', ['loopback', 'uniquelocal']);

    app.use('/', cors({
        methods: ['GET', 'POST'],
        exposedHeaders: [
            'Ratelimit-Limit',
            'Ratelimit-Policy',
            'Ratelimit-Remaining',
            'Ratelimit-Reset'
        ],
        ...corsConfig,
    }));

    app.post('/', (req, res, next) => {
        if (!acceptRegex.test(req.header('Accept'))) {
            return fail(res, "error.api.header.accept");
        }
        if (!acceptRegex.test(req.header('Content-Type'))) {
            return fail(res, "error.api.header.content_type");
        }
        next();
    });

    app.post('/', (req, res, next) => {
        if (!env.apiKeyURL) {
            return next();
        }

        const { success, error } = APIKeys.validateAuthorization(req);
        if (!success) {
            // We call next() here if either if:
            // a) we have user sessions enabled, meaning the request
            //    will still need a Bearer token to not be rejected, or
            // b) we do not require the user to be authenticated, and
            //    so they can just make the request with the regular
            //    rate limit configuration;
            // otherwise, we reject the request.
            if (
                (env.sessionEnabled || !env.authRequired)
                && ['missing', 'not_api_key'].includes(error)
            ) {
                return next();
            }

            return fail(res, `error.api.auth.key.${error}`);
        }

        return next();
    });

    app.post('/', (req, res, next) => {
        if (!env.sessionEnabled || req.rateLimitKey) {
            return next();
        }

        try {
            const authorization = req.header("Authorization");
            if (!authorization) {
                return fail(res, "error.api.auth.jwt.missing");
            }

            if (authorization.length >= 256) {
                return fail(res, "error.api.auth.jwt.invalid");
            }

            const [ type, token, ...rest ] = authorization.split(" ");
            if (!token || type.toLowerCase() !== 'bearer' || rest.length) {
                return fail(res, "error.api.auth.jwt.invalid");
            }

            if (!jwt.verify(token)) {
                return fail(res, "error.api.auth.jwt.invalid");
            }

            req.rateLimitKey = hashHmac(token, 'rate');
        } catch {
            return fail(res, "error.api.generic");
        }
        next();
    });

    app.post('/', apiLimiter);
    app.use('/', express.json({ limit: 10024 }));

    app.use('/', (err, _, res, next) => {
        if (err) {
            const { status, body } = createResponse("error", {
                code: "error.api.invalid_body",
            });
            return res.status(status).json(body);
        }

        next();
    });

    app.post("/session", sessionLimiter, async (req, res) => {
        if (!env.sessionEnabled) {
            return fail(res, "error.api.auth.not_configured")
        }

        const turnstileResponse = req.header("cf-turnstile-response");

        if (!turnstileResponse) {
            return fail(res, "error.api.auth.turnstile.missing");
        }

        const turnstileResult = await verifyTurnstileToken(
            turnstileResponse,
            req.ip
        );

        if (!turnstileResult) {
            return fail(res, "error.api.auth.turnstile.invalid");
        }

        try {
            res.json(jwt.generate());
        } catch {
            return fail(res, "error.api.generic");
        }
    });

    app.post('/', async (req, res) => {
        const request = req.body;

        if (!request.url) {
            return fail(res, "error.api.link.missing");
        }

        const { success, data: normalizedRequest } = await normalizeRequest(request);
        if (!success) {
            return fail(res, "error.api.invalid_body");
        }

        const parsed = extract(normalizedRequest.url);

        if (!parsed) {
            return fail(res, "error.api.link.invalid");
        }
        if ("error" in parsed) {
            let context;
            if (parsed?.context) {
                context = parsed.context;
            }
            return fail(res, `error.api.${parsed.error}`, context);
        }

        try {
            // const cacheKey = `${normalizedRequest.downloadMode}_${parsed.patternMatch.id}`;
            // const cachedResult = await redisClient.get(cacheKey);
            // if (cachedResult) {
            //     const parsedResult = JSON.parse(cachedResult);
            //     return res.status(parsedResult.status).json(parsedResult.body);
            // }
            const result = await match({
                host: parsed.host,
                patternMatch: parsed.patternMatch,
                params: normalizedRequest,
            });
        
            // await redisClient.set(cacheKey, JSON.stringify(result), {
            //     EX: 1200 
            // });
        
            res.status(result.status).json(result.body);
        } catch (error) {
            fail(res, "error.api.generic");
        }
    })

    app.post("/search", async (req, res) => {
        const { query, next, loadmore } = req.body;
        if (!query && !next) {
          return res.status(400).json({ error: "Query parameter is required" });
        }

        if(next && next != '' && loadmore) {
            try {
            // Fetch results from YouTube API if not in cache

            const result = await youtubesearchapi.NextPage(next, false, 6, [{ type: "video" }]);

            // Return the result to the client
            return res.json(result);
            } catch (error) {
                console.error("Error fetching YouTube data:", error);
                return res.status(500).json({ error: "Failed to fetch YouTube search results" });
            }
        }
      
        // Check if the result for the query is already in the cache
        const cachedResult = cache.get(query);
        if (cachedResult) {
          return res.json(cachedResult); // Return cached result
        }
      
        try {
          // Fetch results from YouTube API if not in cache
          const result = await youtubesearchapi.GetListByKeyword(query, false, 6, [{ type: "video" }]);
      
          // Cache the result for 5 days
          cache.set(query, result);
      
          // Return the result to the client
          return res.json(result);
        } catch (error) {
          console.error("Error fetching YouTube data:", error);
          return res.status(500).json({ error: "Failed to fetch YouTube search results" });
        }
    });

    app.get('/stream', apiTunnelLimiter, async (req, res) => {
        const id = String(req.query.id);
        const exp = String(req.query.exp);
        const sig = String(req.query.sig);
        const sec = String(req.query.sec);
        const iv = String(req.query.iv);

        const checkQueries = id && exp && sig && sec && iv;
        const checkBaseLength = id.length === 21 && exp.length === 13;
        const checkSafeLength = sig.length === 43 && sec.length === 43 && iv.length === 22;

        if (!checkQueries || !checkBaseLength || !checkSafeLength) {
            return res.status(400).end();
        }

        if (req.query.p) {
            return res.status(200).end();
        }

        const streamInfo = await verifyStream(id, sig, exp, sec, iv);
        if (!streamInfo?.service) {
            return res.status(streamInfo.status).end();
        }

        if (streamInfo.type === 'proxy') {
            streamInfo.range = req.headers['range'];
        }

        return stream(res, streamInfo);
    })

    app.get('/proxy-image', async (req, res) => {
        const base64ImageUrl = req.query.url; // Expect the image URL as a Base64-encoded string
    
        if (!base64ImageUrl) {
            return res.status(400).send("Base64-encoded image URL is required");
        }
    
        try {
            // Decode the Base64 string to get the actual URL
            const decodedImageUrl = Buffer.from(base64ImageUrl, 'base64').toString('utf-8');
    
            // Fetch the image from the remote server
            const response = await got(decodedImageUrl, { responseType: 'buffer' });
    
            // Set the appropriate content type for the image
            res.set('Content-Type', response.headers['content-type']);
            res.send(response.body); // Send the image binary data to the client
        } catch (error) {
            console.error("Error fetching the image:", error.message);
            res.status(500).send("Failed to fetch image");
        }
    });

    const itunnelHandler = (req, res) => {
        if (!req.ip.endsWith('127.0.0.1')) {
            return res.sendStatus(403);
        }

        if (String(req.query.id).length !== 21) {
            return res.sendStatus(400);
        }

        const streamInfo = getInternalStream(req.query.id);
        console.log(streamInfo);
        if (!streamInfo) {
            return res.sendStatus(404);
        }

        streamInfo.headers = new Map([
            ...(streamInfo.headers || []),
            ...Object.entries(req.headers)
        ]);

        console.log('klala', streamInfo);

        return stream(res, { type: 'internal', data: streamInfo });
    };

    app.get('/itunnel', itunnelHandler);

    app.post('/render-tiktok-video', async (req, res) => {
        const { images, audio, artist } = req.body;
    
        if (!Array.isArray(images) || !audio) {
            return res.status(400).json({ error: 'Please provide an array of image URLs and an audio URL.' });
        }
    
        try {
            const videoURL = await processRequest(images, audio, artist);
            res.json({ downloadUrl: videoURL});
        } catch (error) {
            console.error('Error processing request:', error);
            res.status(500).json({ error: 'An error occurred while processing your request.' });
        }
    });

    app.get('/download-tiktok-video', (req, res) => {

        const file = req.query.file;  // Use query parameter instead of route parameter
        if (!file) {
            return res.status(400).send('Filename query parameter is required');
        }

        const filename = decrypt(file);
        const filePath = path.join(__dirname, 'public/videos', filename);
        
        fs.stat(filePath, (err, stats) => {
            if (err) {
                console.error('File not found:', err);
                return res.status(404).send('File not found');
            }
        
            // Set headers to indicate file download
            res.setHeader('Content-Disposition', `attachment; filename=${filename}`);
            res.setHeader('Content-Length', stats.size);
            res.setHeader('Content-Type', 'application/octet-stream');
        
            const readStream = fs.createReadStream(filePath);
            readStream.pipe(res);

            readStream.on('end', () => {
                fs.unlink(filePath, (unlinkErr) => {
                    if (unlinkErr) {
                        console.error('Error deleting file:', unlinkErr);
                    } else {
                        console.log('File deleted:', filePath);
                    }
                });
            });

            // Handle errors in the read stream
            readStream.on('error', (streamErr) => {
                console.error('Stream error:', streamErr);
                res.status(500).send('Error streaming file');
            });
        });
    });

    app.get('/', (_, res) => {
        res.type('json');
        res.status(200).send("Y2Mate.one Engine");
    })

    app.get('/favicon.ico', (req, res) => {
        res.status(404).end();
    })

    app.get('/*', (req, res) => {
        res.redirect('/');
    })

    // handle all express errors
    app.use((_, __, res, ___) => {
        return fail(res, "error.api.generic");
    })

    randomizeCiphers();
    setInterval(randomizeCiphers, 1000 * 60 * 30); // shuffle ciphers every 30 minutes

    if (env.externalProxy) {
        if (env.freebindCIDR) {
            throw new Error('Freebind is not available when external proxy is enabled')
        }

        setGlobalDispatcher(new ProxyAgent(env.externalProxy))
    }

    http.createServer(app).listen({
        port: env.apiPort,
        host: env.listenAddress,
        reusePort: env.instanceCount > 1 || undefined
    }, () => {
        if (isPrimary) {
            console.log(`\n` +
                Bright(Cyan("cobalt ")) + Bright("API ^ω⁠^") + "\n" +

                "~~~~~~\n" +
                Bright("version: ") + version + "\n" +
                Bright("commit: ") + git.commit + "\n" +
                Bright("branch: ") + git.branch + "\n" +
                Bright("remote: ") + git.remote + "\n" +
                Bright("start time: ") + startTime.toUTCString() + "\n" +
                "~~~~~~\n" +

                Bright("url: ") + Bright(Cyan(env.apiURL)) + "\n" +
                Bright("port: ") + env.apiPort + "\n"
            );
        }

        if (env.apiKeyURL) {
            APIKeys.setup(env.apiKeyURL);
        }

        if (env.cookiePath) {
            Cookies.setup(env.cookiePath);
        }
    });

    if (isCluster) {
        const istreamer = express();
        istreamer.get('/itunnel', itunnelHandler);
        const server = istreamer.listen({
            port: 0,
            host: '127.0.0.1',
            exclusive: true
        }, () => {
            const { port } = server.address();
            console.log(`${Green('[✓]')} cobalt sub-instance running on 127.0.0.1:${port}`);
            setTunnelPort(port);
        });
    }
}
