import { KeyFinder } from "./algorithms/bsgs"
import KeyFinderBrute from "./algorithms/btc_finder_wallet_bruteforce"
import wallets from "../wallets.json"
import btc_bruteforce from "./algorithms/btc_finder_wallet_bruteforce";
import fs from "fs";
import path from "path";

function bsgs() {
    const targetPublicKey = "03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852";
    const startRangeHex = "200000000000000000000000000000000";
    const endRangeHex = "3ffffffffffffffffffffffffffffffff";
    const privateKey = KeyFinder.findPrivateKey(startRangeHex, endRangeHex, targetPublicKey);


    if (privateKey !== null) {
        const privateKeyHex = privateKey.toString(16).padStart(64, '0');
        console.log(`Private key found: ${privateKeyHex}`);
        const filePath = path.join(__dirname, "data", "private_key.txt");
        
        // Ensure the directory exists
        const dir = path.dirname(filePath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
    
        // Write the private key to file
        fs.writeFile(filePath, privateKeyHex, (err) => {
            if (err) {
                console.error("Error writing private key to file:", err);
            } else {
                console.log(`Private key saved to ${filePath}`);
            }
        });
    } else {
        console.log("Private key not found.");
    }
}
function brute_force() {
    const finder = new KeyFinderBrute.KeyFinderBrute();

    // Define the range for private keys
    const startRangeHex = "200000000000000000000000000000000"; // 0 in hexadecimal
    const endRangeHex = "3ffffffffffffffffffffffffffffffff"; // 2^256-1 in hexadecimal

    finder.solvePuzzle("03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852", startRangeHex, endRangeHex);
}

function main() {
    brute_force()
}

main();

