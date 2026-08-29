import { useQuery } from "@tanstack/react-query";
import { useHttp } from "@/hooks/use-ws";
import { useAuthStore } from "@/stores/use-auth-store";
import { queryKeys } from "@/lib/query-keys";
import { SESSION_TOKEN_PREFIX } from "@/lib/constants";
import type { AuthMeResponse } from "@/types/user";

/**
 * The email/password account behind the current session, or null.
 *
 * The query only runs for session tokens. Gateway-token and API-key callers
 * have no account, and browser-paired clients have no bearer token at all, so
 * asking would just produce a guaranteed-empty request on every mount.
 */
export function useCurrentAccount() {
  const http = useHttp();
  const token = useAuthStore((s) => s.token);
  const isSessionToken = token.startsWith(SESSION_TOKEN_PREFIX);

  const { data, isLoading } = useQuery({
    queryKey: queryKeys.accounts.me,
    queryFn: () => http.get<AuthMeResponse>("/v1/auth/me"),
    enabled: isSessionToken,
    staleTime: 5 * 60_000,
  });

  return {
    account: data?.user ?? null,
    memberships: data?.tenants ?? [],
    loading: isLoading,
    /** True while the account still holds a password an administrator chose. */
    mustChangePassword: data?.user?.must_change_password ?? false,
    isSessionToken,
  };
}
