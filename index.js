import fs from 'fs/promises';
import { decryptLink } from './src/decrypt.js';

async function main() {
    try {
        console.log("Fetching Telegram channel...");
        const tgUrl = process.env.TG_CHANNEL_URL;
        if (!tgUrl) {
            console.error("Error: TG_CHANNEL_URL environment variable is not set!");
            process.exit(1);
        }
        const response = await fetch(tgUrl);
        const html = await response.text();

        // The posts are usually inside <div class="tgme_widget_message_text">...</div>
        // Let's try to extract the link for Russia.
        // The structure from the user's prompt:
        // 👇Для России 🇷🇺
        // happ://crypt5/...
        
        // Let's find all occurences of happ:// links
        const happLinks = [...html.matchAll(/happ:\/\/crypt5\/[A-Za-z0-9+/=]+/g)].map(m => m[0]);
        
        if (happLinks.length === 0) {
            console.error("No happ:// links found on the channel.");
            process.exit(1);
        }

        // We assume the last one or we can specifically look for "Для России" then the next link.
        // Given the channel structure, let's just parse the DOM loosely with regex.
        // A more robust way is to split by message blocks and find the one with "Для России".
        
        const messageBlocks = html.split('<div class="tgme_widget_message_text');
        let russiaLink = null;
        
        // Start from the latest message (end of the array)
        for (let i = messageBlocks.length - 1; i >= 1; i--) {
            const block = messageBlocks[i];
            if (block.includes('Для России')) {
                const match = block.match(/happ:\/\/crypt5\/[A-Za-z0-9+/=]+/);
                if (match) {
                    russiaLink = match[0];
                    break;
                }
            }
        }

        if (!russiaLink) {
            console.error("Could not find a happ:// link for Russia in the recent messages.");
            process.exit(1);
        }

        console.log("Found link:", russiaLink.substring(0, 50) + "...");

        console.log("Decrypting link...");
        const decryptedUrl = await decryptLink(russiaLink);
        console.log("Decrypted URL: ***");

        console.log("Fetching subscription data...");
        const subResponse = await fetch(decryptedUrl);
        if (!subResponse.ok) {
            throw new Error(`Failed to fetch subscription: ${subResponse.statusText}`);
        }
        
        const base64Data = await subResponse.text();
        console.log("Successfully fetched base64 subscription. Length:", base64Data.length);

        const outPath = 'base64_player_id_game.txt';
        await fs.writeFile(outPath, base64Data.trim(), 'utf-8');
        console.log(`Saved to ${outPath}`);

    } catch (err) {
        console.error("Error during execution:", err);
        process.exit(1);
    }
}

main();
