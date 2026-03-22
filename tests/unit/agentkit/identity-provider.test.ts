import { describe, expect, beforeEach, it } from "vitest";
import { KMS, KmsKeyType } from "@0xpolygonid/js-sdk";
import { getRandomBytes } from "@iden3/js-crypto";
import { Blockchain, DidMethod, NetworkId } from "@iden3/js-iden3-core";
import {
  generateChallenge,
  createDidDoc,
  createDefaultDid,
  EthereumWallet,
  getKeyInfoFromKMS,
  registerAgentInMemorySecp256k1KMS,
  packDIDChallenge,
  decodeAuthToken,
  checkOwnerAuthToken,
  packOwnerAuthDid,
  packResponseArtifactsChallenge,
  verifyAgentResponse,
} from "../../../src";

const rpcUrl = "https://rpc-testnet.billions.network";

const DID_CONFIG = {
  method: DidMethod.Iden3,
  blockchain: Blockchain.Billions,
  network: NetworkId.Test,
};

describe("IdentityProvider", () => {
  let agentKMS: KMS;
  let agentSeed: Uint8Array;
  let agentWallet: EthereumWallet;
  let agentAddress: string;

  let ownerKMS: KMS;
  let ownerSeed: Uint8Array;
  let ownerWallet: EthereumWallet;
  let ownerAddress: string;

  beforeEach(async () => {
    agentKMS = registerAgentInMemorySecp256k1KMS();
    agentSeed = getRandomBytes(32);
    agentWallet = new EthereumWallet(rpcUrl, agentKMS);
    const agentKeyRef = await agentKMS.createKeyFromSeed(
      KmsKeyType.Secp256k1,
      agentSeed
    );
    agentAddress = await agentWallet.getEthAddress(agentKeyRef);

    ownerKMS = registerAgentInMemorySecp256k1KMS();
    ownerSeed = getRandomBytes(32);
    ownerWallet = new EthereumWallet(rpcUrl, ownerKMS);
    const ownerKeyRef = await ownerKMS.createKeyFromSeed(
      KmsKeyType.Secp256k1,
      ownerSeed
    );
    ownerAddress = await ownerWallet.getEthAddress(ownerKeyRef);
  });

  describe("generateChallenge", () => {
    it("returns a number within 60 seconds of current time", () => {
      const now = Math.floor(Date.now() / 1000);
      const challenge = generateChallenge();

      expect(typeof challenge).toBe("number");
      expect(challenge).toBeGreaterThanOrEqual(now - 60);
      expect(challenge).toBeLessThanOrEqual(now + 60);
    });
  });

  describe("createDefaultDid", () => {
    it("deterministic — same address gives same DID", () => {
      const did1 = createDefaultDid(ownerAddress);
      const did2 = createDefaultDid(ownerAddress);

      expect(did1.string()).toEqual(did2.string());
    });
  });

  describe("createDidDoc", () => {
    it("creates DID document with correct id and ethereum address", () => {
      const did =
        "did:iden3:billions:test:2VxnoiNqdMPycqn9jdaYNKYugRDA1ewYP2n63ad1wa";

      const doc = createDidDoc(did, ownerAddress);

      expect(doc.id).toBe(did);
      expect(doc.verificationMethod).toHaveLength(1);
      expect(doc.verificationMethod[0].type).toBe(
        "EcdsaSecp256k1RecoveryMethod2020"
      );
      expect(doc.verificationMethod[0].ethereumAddress).toBe(ownerAddress);
    });
  });

  describe("getKeyInfoFromKMS", () => {
    it("returns correct data", async () => {
      const { keyId, ethAddress, did, id } = await getKeyInfoFromKMS(
        agentKMS,
        KmsKeyType.Secp256k1,
        DID_CONFIG,
        agentWallet
      );

      expect(agentAddress).toEqual(ethAddress);
      expect(did.string()).toContain(id.string());
      expect(did.string()).toContain("did:iden3:billions:test:");
      expect(id.bigInt()).toBeGreaterThan(0n);
    });
  });

  describe("packDIDChallenge", () => {
    it("packed token can be unpacked and returns original payload", async () => {
      const { keyId, ethAddress, did } = await getKeyInfoFromKMS(
        agentKMS,
        KmsKeyType.Secp256k1,
        DID_CONFIG,
        agentWallet
      );

      const didDoc = createDidDoc(did.string(), ethAddress);
      const challenge = generateChallenge();

      const jws = await packDIDChallenge(
        agentKMS,
        keyId,
        {
          did: did.string(),
          challenge: challenge,
        },
        didDoc,
        { seed: agentSeed }
      );

      const decode = await decodeAuthToken(jws, {
        did: did.string(),
        address: ethAddress,
      });

      expect(decode.from).toEqual(did.string());
      expect(decode.challenge).toEqual(challenge.toString());
    });
  });

  describe("packOwnerAuthDid", () => {
    it("packed token can be unpacked and returns original payload", async () => {
      const challenge = generateChallenge();

      const jws = await packOwnerAuthDid(
        ownerKMS,
        KmsKeyType.Secp256k1,
        DID_CONFIG,
        challenge,
        ownerWallet
      );

      const ownerDid = createDefaultDid(ownerAddress).string();

      const decode = await decodeAuthToken(jws, {
        did: ownerDid,
        address: ownerAddress,
      });

      expect(decode.from).toEqual(ownerDid);
      expect(decode.challenge).toEqual(challenge);
    });
  });

  describe("checkOwnerAuthToken", () => {
    it("rejects expired challenge", async () => {
      const expiredChallenge = Math.floor(Date.now() / 1000) - 301;

      const jws = await packOwnerAuthDid(
        ownerKMS,
        KmsKeyType.Secp256k1,
        DID_CONFIG,
        expiredChallenge,
        ownerWallet
      );

      const ownerDid = createDefaultDid(ownerAddress).string();

      await expect(
        checkOwnerAuthToken({
          signedToken: jws,
          did: ownerDid,
          ethAddress: ownerAddress,
        })
      ).rejects.toThrow("Challenge is expired");
    });

    it("rejects wrong key", async () => {
      const challenge = generateChallenge();
      const jws = await packOwnerAuthDid(
        ownerKMS,
        KmsKeyType.Secp256k1,
        DID_CONFIG,
        challenge,
        ownerWallet
      );

      const ownerDid = createDefaultDid(ownerAddress).string();

      await expect(
        checkOwnerAuthToken({
          signedToken: jws,
          did: ownerDid,
          ethAddress: agentAddress,
        })
      ).rejects.toThrow();
    });
  });

  describe("verifyAgentResponse", () => {
    it("verifies a response signed by the agent", async () => {
      const { keyId, ethAddress, did } = await getKeyInfoFromKMS(
        agentKMS,
        KmsKeyType.Secp256k1,
        DID_CONFIG,
        agentWallet
      );

      const challenge = generateChallenge();

      const payload = {
        did: did.string(),
        ethAddress,
        challenge,
        response: "test response",
      };

      const didDoc = createDidDoc(did.string(), ethAddress);

      const jws = await packResponseArtifactsChallenge(
        agentKMS,
        keyId,
        payload,
        didDoc,
        {
          seed: agentSeed,
        }
      );

      await expect(
        verifyAgentResponse({
          did: did.string(),
          ethAddress,
          challenge,
          response: "test response",
          signedResponseToken: jws,
        })
      ).resolves.toBeUndefined();
    });
  });
});
