// Import the necessary Hardhat libraries
import { ethers } from "hardhat";
import { expect } from "chai";

// Describe the contract being tested
describe("SecretStorage", function () {
  let secretStorage;
  let owner, party1, party2;

  // Deploy the contract before each test
  beforeEach(async function () {
    [owner, party1, party2] = await ethers.getSigners();

    const SecretStorage = await ethers.getContractFactory("SecretStorage");
    secretStorage = await SecretStorage.deploy();
    secretStorage.waitForDeployment();

  });

  // Write individual test cases
  it("should store and reveal the secret", async function () {
    const secret = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"; // Example secret
    const hashedSecret = ethers.keccak256(secret); //maybe encode into string to save on storing 66 bytes
    const hashedSecretLength = new Blob([hashedSecret]).size;
    const prefixedMessage = ethers.toUtf8Bytes(
      "\x19Ethereum Signed Message:\n" + hashedSecretLength + hashedSecret 
      );
    const messageHash = ethers.keccak256(prefixedMessage);
    
    console.log("Length: ");
    console.log(String(hashedSecretLength));
    console.log("Prefix: ")
    console.log(ethers.hexlify(ethers.toUtf8Bytes("\x19Ethereum Signed Message:\n")));
    console.log("Hashed Secret: ");
    console.log(hashedSecret);
    console.log("Hashed Secret Bytes: ");
    console.log(ethers.hexlify(ethers.toUtf8Bytes(hashedSecret)));
    console.log("Prefixed Message: ");
    console.log(ethers.hexlify(prefixedMessage));
    console.log("Message Hash: ");
    console.log(messageHash);
      
    // Generate signatures
    const otherSignature = await party2.signMessage(hashedSecret);
    
    console.log("Second address: ");
    console.log(party2.address);

    // Store the secret
    await secretStorage.connect(party1).storeSecret(
      messageHash,
      otherSignature
    );

    // Verify the secret is stored
    const storedSecret = await secretStorage.getSecretHash(party1.address);
    expect(storedSecret).to.equal(messageHash, "Secret not stored correctly");

    // Verify the signers are correct
    const storedSigner1 = await secretStorage.getSigner1(party1.address);
    expect(storedSigner1).to.equal(party1.address, "Signer not stored correctly");

    const storedSigner2 = await secretStorage.getSigner2(party1.address);
    expect(storedSigner2).to.equal(party2.address, "Signer not stored correctly");

    // Reveal the secret
    await secretStorage.connect(party1).revealSecret(secret);

    // Verify the secret is deleted
    const revealedSecret = await secretStorage.getSecretHash(party1.address);
    expect(revealedSecret).to.equal("0x0000000000000000000000000000000000000000000000000000000000000000", "Secret not deleted");
  });

});