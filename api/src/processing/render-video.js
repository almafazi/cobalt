import fs from 'fs';
import path from 'path';
import ffmpegPath from 'ffmpeg-static';
import { exec } from 'child_process';
import tmp from 'tmp';
import got from 'got';
import { encrypt } from '../misc/crypto.js';
import { env } from '../config.js';

const downloadFile = async (url, outputPath) => {
    const { body } = await got(url, { responseType: 'buffer' });
    fs.writeFileSync(outputPath, body);
};

const createVideo = (imagePaths, audioPath, outputPath) => {
    return new Promise((resolve, reject) => {
        // Prepare the images input string
        const imagesInput = imagePaths
            .map((image, index) => `-loop 1 -t 5 -i ${image}`)
            .join(' ');

        // Prepare the filter complex
        const filters = imagePaths
            .map((_, index) => `[${index}:v]scale=1080:1440:force_original_aspect_ratio=decrease,pad=1080:1440:(1080-iw)/2:(1440-ih)/2,setpts=N/FRAME_RATE/TB[v${index}]`)
            .join('; ');

        const filterComplex = `${filters}; ${imagePaths.map((_, index) => `[v${index}]`).join('')}concat=n=${imagePaths.length}:v=1:a=0[outv]`;

        // Construct the FFmpeg command
        const command = `${ffmpegPath} ${imagesInput} -i ${audioPath} -filter_complex "${filterComplex}" -map "[outv]" -map ${imagePaths.length}:a -c:v libx264 -pix_fmt yuv420p -c:a aac -shortest ${outputPath}`;

        // Execute the command
        exec(command, (error, stdout, stderr) => {
            if (error) {
                return reject(error);
            }
            if (stderr) {
                console.error(`FFmpeg stderr: ${stderr}`);
            }
            console.log('Video created successfully:', outputPath);
            resolve(outputPath);
        });
    });
};


const processRequest = async (images, audio, artist) => {
    // Create a temporary directory for processing
    const tempDir = tmp.dirSync({ unsafeCleanup: true });

    // Define output directory and ensure it exists
    const outputDir = path.join('public', 'videos');
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }

    try {
        // Download images
        const imagePaths = await Promise.all(
            images.map((image, index) => {
                const imagePath = path.join(tempDir.name, `image${index + 1}.jpg`);
                return downloadFile(image.url, imagePath).then(() => imagePath);
            })
        );

        // Download audio
        const audioPath = path.join(tempDir.name, 'audio.mp3');
        await downloadFile(audio, audioPath);

        // Create output video filename and path
        const outputFilename = `${artist}_${Date.now()}.mp4`;
        const outputPath = path.join(outputDir, outputFilename);
        
        // Create video
        await createVideo(imagePaths, audioPath, outputPath);

        const sendurl = new URL(`/download-tiktok-video?file=${encrypt(outputFilename)}`, env.apiURL)
        // Return the relative path to the video
        return sendurl.toString();
    } catch (error) {
        console.error('Error processing request:', error);
        throw error; // Propagate error to be handled by the caller
    } finally {
        // Clean up temporary directory
        tempDir.removeCallback();
    }
};

export default processRequest;
