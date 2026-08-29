/** An email + password account, as returned by /v1/users and /v1/auth/me. */
export interface UserAccount {
  id: string;
  /** Identity string used across tenant membership and resource ownership. */
  user_id: string;
  email: string;
  display_name: string;
  status: "active" | "disabled";
  must_change_password: boolean;
  last_login_at: string | null;
  created_at: string;
}

/** A tenant the account belongs to, with the role it holds there. */
export interface UserTenantMembership {
  tenant_id: string;
  name: string;
  slug: string;
  role: string;
}

export interface UserCreateInput {
  email: string;
  password: string;
  /** Optional; derived from the email local part when omitted. */
  user_id?: string;
  display_name?: string;
  /** Tenant UUID or slug. Without it the account signs in with no membership. */
  tenant_id?: string;
  tenant_role?: string;
  must_change_password?: boolean;
}

export interface UserCreateResponse {
  user: UserAccount;
  tenants: UserTenantMembership[];
}

export interface UserUpdateInput {
  display_name?: string;
  status?: "active" | "disabled";
  must_change_password?: boolean;
}

/** Response of GET /v1/auth/me. `user` is null for gateway-token or API-key callers. */
export interface AuthMeResponse {
  user: UserAccount | null;
  user_id: string;
  role: string;
  tenant_id: string;
  tenants: UserTenantMembership[];
}
