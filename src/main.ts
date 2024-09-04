import { KeyFinder } from "./algorithms/bsgs"
import wallets from "../wallets.json"
import btc_bruteforce from "./algorithms/btc_finder_wallet_bruteforce";
import fs from "fs";
import path from "path";

function bsgs() {
    const targetPublicKey = "033c4a45cbd643ff97d77f41ea37e843648d50fd894b864b0d52febc62f6454f7c";
    const startRangeHex = "80000";
    const endRangeHex = "fffff";
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
    const finder = new btc_bruteforce.KeyFinder();

    // Define the range for private keys
    const startRangeHex = "20000000"; // 0 in hexadecimal
    const endRangeHex = "3fffffff"; // 2^256-1 in hexadecimal

    finder.solvePuzzle("030d282cf2ff536d2c42f105d0b8588821a915dc3f9a05bd98bb23af67a2e92a5b", startRangeHex, endRangeHex);
}

function main() {
    bsgs()
}

main();

