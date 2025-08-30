import { describe, expect, it, vi, beforeEach } from "vitest";

// Interfaces for type safety
interface ClarityResponse<T> {
  ok: boolean;
  value: T | number; // number for error codes
}

interface Credential {
  hash: Uint8Array; // Represent buff 32 as Uint8Array
  issuer: string;
  learner: string;
  title: string;
  description: string;
  timestamp: number;
  expiry: number | null;
  revoked: boolean;
  metadata: string;
}

interface Endorsement {
  endorsementNote: string;
  timestamp: number;
}

interface Category {
  category: string;
  tags: string[];
}

interface AccessGrant {
  grantedAt: number;
  expiresAt: number | null;
}

interface ContractState {
  credentialCounter: number;
  contractPaused: boolean;
  contractAdmin: string;
  credentials: Map<number, Credential>;
  credentialHashes: Map<string, { credentialId: number }>; // Hash as hex string for map key
  endorsements: Map<string, Endorsement>; // Key as `${credentialId}-${endorser}`
  categories: Map<number, Category>;
  accessGrants: Map<string, AccessGrant>; // Key as `${credentialId}-${grantee}`
}

// Helper to convert buff to hex string for map keys
const buffToHex = (buff: Uint8Array): string => Array.from(buff).map(b => b.toString(16).padStart(2, '0')).join('');

// Mock contract implementation
class CredentialStorageMock {
  private state: ContractState = {
    credentialCounter: 0,
    contractPaused: false,
    contractAdmin: "deployer",
    credentials: new Map(),
    credentialHashes: new Map(),
    endorsements: new Map(),
    categories: new Map(),
    accessGrants: new Map(),
  };

  private ERR_UNAUTHORIZED = 100;
  private ERR_CREDENTIAL_EXISTS = 101;
  private ERR_INVALID_HASH = 102;
  private ERR_INVALID_TITLE = 103;
  private ERR_INVALID_DESCRIPTION = 104;
  private ERR_NOT_FOUND = 105;
  private ERR_ALREADY_REVOKED = 106;
  private ERR_NOT_OWNER = 107;
  private ERR_INVALID_EXPIRY = 108;
  private ERR_METADATA_TOO_LONG = 109;
  private ERR_INVALID_CATEGORY = 110;
  private ERR_PAUSED = 111;
  private ERR_INVALID_ENDORSER = 112;
  private MAX_TITLE_LEN = 100;
  private MAX_DESCRIPTION_LEN = 500;
  private MAX_METADATA_LEN = 1000;
  private MAX_TAGS = 10;

  // Simulate block-height
  private currentBlockHeight = 1000;

  private incrementBlockHeight() {
    this.currentBlockHeight += 1;
  }

  storeCredential(
    caller: string,
    hash: Uint8Array,
    issuer: string,
    learner: string,
    title: string,
    description: string,
    expiry: number | null,
    metadata: string
  ): ClarityResponse<number> {
    if (this.state.contractPaused) {
      return { ok: false, value: this.ERR_PAUSED };
    }
    if (caller !== issuer) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    if (hash.length === 0) {
      return { ok: false, value: this.ERR_INVALID_HASH };
    }
    if (title.length === 0 || title.length > this.MAX_TITLE_LEN) {
      return { ok: false, value: this.ERR_INVALID_TITLE };
    }
    if (description.length > this.MAX_DESCRIPTION_LEN) {
      return { ok: false, value: this.ERR_INVALID_DESCRIPTION };
    }
    if (metadata.length > this.MAX_METADATA_LEN) {
      return { ok: false, value: this.ERR_METADATA_TOO_LONG };
    }
    const hashHex = buffToHex(hash);
    if (this.state.credentialHashes.has(hashHex)) {
      return { ok: false, value: this.ERR_CREDENTIAL_EXISTS };
    }
    const credentialId = ++this.state.credentialCounter;
    this.state.credentials.set(credentialId, {
      hash,
      issuer,
      learner,
      title,
      description,
      timestamp: this.currentBlockHeight,
      expiry,
      revoked: false,
      metadata,
    });
    this.state.credentialHashes.set(hashHex, { credentialId });
    return { ok: true, value: credentialId };
  }

  revokeCredential(caller: string, credentialId: number): ClarityResponse<boolean> {
    if (this.state.contractPaused) {
      return { ok: false, value: this.ERR_PAUSED };
    }
    const cred = this.state.credentials.get(credentialId);
    if (!cred) {
      return { ok: false, value: this.ERR_NOT_FOUND };
    }
    if (cred.issuer !== caller) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    if (cred.revoked) {
      return { ok: false, value: this.ERR_ALREADY_REVOKED };
    }
    this.state.credentials.set(credentialId, { ...cred, revoked: true });
    return { ok: true, value: true };
  }

  addEndorsement(caller: string, credentialId: number, note: string): ClarityResponse<boolean> {
    if (this.state.contractPaused) {
      return { ok: false, value: this.ERR_PAUSED };
    }
    const cred = this.state.credentials.get(credentialId);
    if (!cred) {
      return { ok: false, value: this.ERR_NOT_FOUND };
    }
    if (cred.revoked) {
      return { ok: false, value: this.ERR_ALREADY_REVOKED };
    }
    const key = `${credentialId}-${caller}`;
    this.state.endorsements.set(key, {
      endorsementNote: note,
      timestamp: this.currentBlockHeight,
    });
    return { ok: true, value: true };
  }

  addCategory(caller: string, credentialId: number, category: string, tags: string[]): ClarityResponse<boolean> {
    if (this.state.contractPaused) {
      return { ok: false, value: this.ERR_PAUSED };
    }
    const cred = this.state.credentials.get(credentialId);
    if (!cred) {
      return { ok: false, value: this.ERR_NOT_FOUND };
    }
    if (cred.issuer !== caller && cred.learner !== caller) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    if (category.length === 0) {
      return { ok: false, value: this.ERR_INVALID_CATEGORY };
    }
    this.state.categories.set(credentialId, { category, tags });
    return { ok: true, value: true };
  }

  grantAccess(caller: string, credentialId: number, grantee: string, expiresAt: number | null): ClarityResponse<boolean> {
    if (this.state.contractPaused) {
      return { ok: false, value: this.ERR_PAUSED };
    }
    const cred = this.state.credentials.get(credentialId);
    if (!cred) {
      return { ok: false, value: this.ERR_NOT_FOUND };
    }
    if (cred.learner !== caller) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    const key = `${credentialId}-${grantee}`;
    this.state.accessGrants.set(key, {
      grantedAt: this.currentBlockHeight,
      expiresAt,
    });
    return { ok: true, value: true };
  }

  pauseContract(caller: string): ClarityResponse<boolean> {
    if (caller !== this.state.contractAdmin) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    this.state.contractPaused = true;
    return { ok: true, value: true };
  }

  unpauseContract(caller: string): ClarityResponse<boolean> {
    if (caller !== this.state.contractAdmin) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    this.state.contractPaused = false;
    return { ok: true, value: true };
  }

  setAdmin(caller: string, newAdmin: string): ClarityResponse<boolean> {
    if (caller !== this.state.contractAdmin) {
      return { ok: false, value: this.ERR_UNAUTHORIZED };
    }
    this.state.contractAdmin = newAdmin;
    return { ok: true, value: true };
  }

  getCredentialDetails(credentialId: number): ClarityResponse<Credential | null> {
    return { ok: true, value: this.state.credentials.get(credentialId) ?? null };
  }

  getCredentialByHash(hash: Uint8Array): ClarityResponse<Credential | null> {
    const hashHex = buffToHex(hash);
    const entry = this.state.credentialHashes.get(hashHex);
    if (!entry) {
      return { ok: true, value: null };
    }
    return this.getCredentialDetails(entry.credentialId);
  }

  getEndorsement(credentialId: number, endorser: string): ClarityResponse<Endorsement | null> {
    const key = `${credentialId}-${endorser}`;
    return { ok: true, value: this.state.endorsements.get(key) ?? null };
  }

  getCategory(credentialId: number): ClarityResponse<Category | null> {
    return { ok: true, value: this.state.categories.get(credentialId) ?? null };
  }

  hasAccess(credentialId: number, viewer: string): ClarityResponse<boolean> {
    const key = `${credentialId}-${viewer}`;
    const grant = this.state.accessGrants.get(key);
    if (!grant) {
      return { ok: true, value: false };
    }
    if (grant.expiresAt !== null && this.currentBlockHeight > grant.expiresAt) {
      return { ok: true, value: false };
    }
    return { ok: true, value: true };
  }

  isValidCredential(credentialId: number): ClarityResponse<boolean> {
    const cred = this.state.credentials.get(credentialId);
    if (!cred) {
      return { ok: true, value: false };
    }
    let valid = !cred.revoked;
    if (cred.expiry !== null) {
      valid = valid && this.currentBlockHeight < cred.expiry;
    }
    return { ok: true, value: valid };
  }

  getCounter(): ClarityResponse<number> {
    return { ok: true, value: this.state.credentialCounter };
  }

  isContractPaused(): ClarityResponse<boolean> {
    return { ok: true, value: this.state.contractPaused };
  }
}

// Test setup
const accounts = {
  deployer: "deployer",
  issuer: "issuer",
  learner: "learner",
  endorser: "endorser",
  grantee: "grantee",
  unauthorized: "unauthorized",
};

const mockHash = new Uint8Array(32).fill(1); // Sample buff 32

describe("CredentialStorage Contract", () => {
  let contract: CredentialStorageMock;

  beforeEach(() => {
    contract = new CredentialStorageMock();
    vi.resetAllMocks();
  });

  it("should store a new credential successfully", () => {
    const result = contract.storeCredential(
      accounts.issuer,
      mockHash,
      accounts.issuer,
      accounts.learner,
      "Python Certification",
      "Completed Python course",
      null,
      "{\"level\": \"intermediate\"}"
    );
    expect(result).toEqual({ ok: true, value: 1 });
    const details = contract.getCredentialDetails(1);
    expect(details.ok).toBe(true);
    expect(details.value).toMatchObject({
      title: "Python Certification",
      description: "Completed Python course",
      revoked: false,
    });
  });

  it("should prevent storing duplicate hash", () => {
    contract.storeCredential(
      accounts.issuer,
      mockHash,
      accounts.issuer,
      accounts.learner,
      "Title",
      "Desc",
      null,
      "Meta"
    );
    const duplicate = contract.storeCredential(
      accounts.issuer,
      mockHash,
      accounts.issuer,
      accounts.learner,
      "Title2",
      "Desc2",
      null,
      "Meta2"
    );
    expect(duplicate).toEqual({ ok: false, value: 101 });
  });

  it("should allow issuer to revoke credential", () => {
    contract.storeCredential(
      accounts.issuer,
      mockHash,
      accounts.issuer,
      accounts.learner,
      "Title",
      "Desc",
      null,
      "Meta"
    );
    const revoke = contract.revokeCredential(accounts.issuer, 1);
    expect(revoke).toEqual({ ok: true, value: true });
    const details = contract.getCredentialDetails(1);
    expect(details.value?.revoked).toBe(true);
  });

  it("should prevent non-issuer from revoking", () => {
    contract.storeCredential(
      accounts.issuer,
      mockHash,
      accounts.issuer,
      accounts.learner,
      "Title",
      "Desc",
      null,
      "Meta"
    );
    const revoke = contract.revokeCredential(accounts.unauthorized, 1);
    expect(revoke).toEqual({ ok: false, value: 100 });
  });

  it("should add endorsement", () => {
    contract.storeCredential(
      accounts.issuer,
      mockHash,
      accounts.issuer,
      accounts.learner,
      "Title",
      "Desc",
      null,
      "Meta"
    );
    const add = contract.addEndorsement(accounts.endorser, 1, "Great work!");
    expect(add).toEqual({ ok: true, value: true });
    const endorsement = contract.getEndorsement(1, accounts.endorser);
    expect(endorsement.value?.endorsementNote).toBe("Great work!");
  });

  it("should add category by issuer or learner", () => {
    contract.storeCredential(
      accounts.issuer,
      mockHash,
      accounts.issuer,
      accounts.learner,
      "Title",
      "Desc",
      null,
      "Meta"
    );
    const add = contract.addCategory(accounts.learner, 1, "Programming", ["python", "coding"]);
    expect(add).toEqual({ ok: true, value: true });
    const cat = contract.getCategory(1);
    expect(cat.value?.category).toBe("Programming");
  });

  it("should grant access by learner", () => {
    contract.storeCredential(
      accounts.issuer,
      mockHash,
      accounts.issuer,
      accounts.learner,
      "Title",
      "Desc",
      null,
      "Meta"
    );
    const grant = contract.grantAccess(accounts.learner, 1, accounts.grantee, null);
    expect(grant).toEqual({ ok: true, value: true });
    const hasAccess = contract.hasAccess(1, accounts.grantee);
    expect(hasAccess).toEqual({ ok: true, value: true });
  });

  it("should pause and unpause contract", () => {
    const pause = contract.pauseContract(accounts.deployer);
    expect(pause).toEqual({ ok: true, value: true });
    expect(contract.isContractPaused()).toEqual({ ok: true, value: true });

    const storeDuringPause = contract.storeCredential(
      accounts.issuer,
      mockHash,
      accounts.issuer,
      accounts.learner,
      "Title",
      "Desc",
      null,
      "Meta"
    );
    expect(storeDuringPause).toEqual({ ok: false, value: 111 });

    const unpause = contract.unpauseContract(accounts.deployer);
    expect(unpause).toEqual({ ok: true, value: true });
    expect(contract.isContractPaused()).toEqual({ ok: true, value: false });
  });

  it("should validate credential expiry", () => {
    contract.storeCredential(
      accounts.issuer,
      mockHash,
      accounts.issuer,
      accounts.learner,
      "Title",
      "Desc",
      1005, // Expiry at 1005
      "Meta"
    );
    const isValid = contract.isValidCredential(1);
    expect(isValid).toEqual({ ok: true, value: true });

    // Simulate block advance
    for (let i = 0; i < 6; i++) {
      contract.incrementBlockHeight(); // Assuming we add a method to increment
    }
    const expired = contract.isValidCredential(1);
    expect(expired).toEqual({ ok: true, value: false });
  });

  it("should prevent metadata too long", () => {
    const longMeta = "a".repeat(1001);
    const result = contract.storeCredential(
      accounts.issuer,
      mockHash,
      accounts.issuer,
      accounts.learner,
      "Title",
      "Desc",
      null,
      longMeta
    );
    expect(result).toEqual({ ok: false, value: 109 });
  });
});