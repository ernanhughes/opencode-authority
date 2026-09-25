export type DataOperation = "ACCESS" | "PROCESS" | "INFER" | "RETAIN" | "REUSE" | "DISCLOSE";
export type ExternalKind = "ACT" | "SPEAK" | "DISCOVER";
export type SpeechAct = "INFORM" | "ASSERT" | "REQUEST" | "OFFER" | "NEGOTIATE" | "ACCEPT" | "PROMISE";
export type Verdict = "ALLOW" | "DENY" | "REQUIRE_APPROVAL" | "REFORMULATE";

export interface SourceRef {
  id: string;
  kind: string;
  uri?: string;
  scope?: string;
}

export interface DataUse {
  source: SourceRef;
  operation: DataOperation;
  /** Declared necessary for the purpose. Absent/unlisted uses fail necessity. */
  necessary?: boolean;
  recipient?: string;
  derivative?: string;
  /** True when the information implicates someone other than the principal. */
  third_party?: boolean;
}

export interface ExternalOperation {
  kind: ExternalKind;
  action: string;
  target?: string;
  counterparty?: string;
  /** Speech only. */
  speech_act?: SpeechAct;
  audience?: string;
  topics?: string[];
  /** Discovery only: predicate identifier; must be listed in a discovery grant. */
  predicate?: string;
}

export interface AuthorityProposal {
  proposal_id: string;
  purpose: string;
  external_operation?: ExternalOperation;
  data_uses: DataUse[];
  required_inputs?: string[];
  irreversible_effects?: string[];
  requested_at?: string;
}

export interface DataUseAuthority {
  id: string;
  purpose: string;
  data_scope: string[];
  permitted_operations: DataOperation[];
  recipients?: string[];
  retention?: string;
  derivative_policy?: string;
  third_party_allowed?: boolean;
  expires_at?: string;
}

export interface ActionGrant {
  id: string;
  purpose: string;
  action_scope: string[];
  targets?: string[];
  consequence_limit?: string;
  approval: "none" | "required";
  expires_at?: string;
}

export interface SpeechGrant {
  id: string;
  purpose: string;
  audience_scope?: string[];
  topic_scope?: string[];
  permitted_acts?: SpeechAct[];
  disclosure_scope?: string[];
  approval: "none" | "required";
  expires_at?: string;
}

export interface DiscoveryGrant {
  id: string;
  purpose: string;
  permitted_predicates: string[];
  approval: "none" | "required";
  expires_at?: string;
}

export interface Revocation {
  id: string;
  revoked_at: string;
}

export interface AuthorityPolicy {
  version: string;
  data_use: DataUseAuthority[];
  actions: ActionGrant[];
  speech?: SpeechGrant[];
  discovery?: DiscoveryGrant[];
  revoked?: Revocation[];
  /** Scope sets that must never combine for the stated purpose. */
  forbidden_combinations?: string[][];
}

export interface DerivedStateRef {
  id: string;
  derived_from: string[];
  purpose: string;
  authority_source: string[];
  permitted_uses: string[];
  expires_at?: string;
}

export type ReasonCode =
  | "PURPOSE_UNAUTHORISED"
  | "DATA_SCOPE_UNAUTHORISED"
  | "OPERATION_UNAUTHORISED"
  | "UNNECESSARY_DATA_USE"
  | "INFERENCE_UNAUTHORISED"
  | "RETENTION_UNAUTHORISED"
  | "REUSE_UNAUTHORISED"
  | "DISCLOSURE_UNAUTHORISED"
  | "ACTION_UNAUTHORISED"
  | "SPEECH_UNAUTHORISED"
  | "DISCOVERY_UNAUTHORISED"
  | "APPROVAL_REQUIRED"
  | "COUNTERPARTY_CONSTRAINT"
  | "POLICY_EXPIRED"
  | "POLICY_INVALID"
  | "COMPOSED_PRIVILEGE"
  | "THIRD_PARTY_BOUNDARY"
  | "REVOCATION_ACTIVE";

export interface CheckResult {
  ok: boolean;
  code: ReasonCode;
  detail: string;
  grant_id?: string;
}

export interface DataUseReceipt {
  source_id: string;
  operation: DataOperation;
  result: "allowed" | "denied" | "approval_required";
  reasons: CheckResult[];
}

export interface AuthorityReceipt {
  receipt_id: string;
  proposal_id: string;
  purpose: string;
  verdict: Verdict;
  data_receipts: DataUseReceipt[];
  action_result?: CheckResult;
  reformulation?: string;
  approval_required_by?: string[];
  revocation_active: boolean;
  composed_scopes: string[];
  irreversible_effects: string[];
  policy_version: string;
}

export interface RevocationImpact {
  future_operations_stopped: string[];
  retained_sources: string[];
  retained_derivatives: string[];
  prior_disclosures: string[];
  irreversible_effects: string[];
  note: string;
}

export type AuthorityFailureCode = "POLICY_INVALID" | "PROPOSAL_INVALID";

export class AuthorityError extends Error {
  readonly code: AuthorityFailureCode;
  constructor(code: AuthorityFailureCode, message: string) {
    super(message);
    this.name = "AuthorityError";
    this.code = code;
  }
}
