import { useCallback } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import i18next from "i18next";
import { useHttp } from "@/hooks/use-ws";
import { queryKeys } from "@/lib/query-keys";
import { toast } from "@/stores/use-toast-store";
import type {
  UserAccount,
  UserCreateInput,
  UserCreateResponse,
  UserUpdateInput,
} from "@/types/user";

export function useUsers() {
  const http = useHttp();
  const queryClient = useQueryClient();

  const { data: users = [], isLoading: loading } = useQuery({
    queryKey: queryKeys.accounts.all,
    queryFn: () => http.get<UserAccount[]>("/v1/users"),
    staleTime: 60_000,
  });

  const invalidate = useCallback(
    () => queryClient.invalidateQueries({ queryKey: queryKeys.accounts.all }),
    [queryClient],
  );

  const createUser = useCallback(
    async (data: UserCreateInput): Promise<UserCreateResponse> => {
      try {
        const res = await http.post<UserCreateResponse>("/v1/users", data);
        await invalidate();
        toast.success(i18next.t("users:toast.created"));
        return res;
      } catch (err) {
        toast.error(i18next.t("users:toast.failedCreate"), err instanceof Error ? err.message : "");
        throw err;
      }
    },
    [http, invalidate],
  );

  const updateUser = useCallback(
    async (id: string, data: UserUpdateInput) => {
      try {
        await http.patch(`/v1/users/${id}`, data);
        await invalidate();
        toast.success(i18next.t("users:toast.updated"));
      } catch (err) {
        toast.error(i18next.t("users:toast.failedUpdate"), err instanceof Error ? err.message : "");
        throw err;
      }
    },
    [http, invalidate],
  );

  const deleteUser = useCallback(
    async (id: string) => {
      try {
        await http.delete(`/v1/users/${id}`);
        await invalidate();
        toast.success(i18next.t("users:toast.deleted"));
      } catch (err) {
        toast.error(i18next.t("users:toast.failedDelete"), err instanceof Error ? err.message : "");
        throw err;
      }
    },
    [http, invalidate],
  );

  const setPassword = useCallback(
    async (id: string, newPassword: string, mustChange: boolean) => {
      try {
        await http.post(`/v1/users/${id}/password`, {
          new_password: newPassword,
          must_change_password: mustChange,
        });
        await invalidate();
        toast.success(i18next.t("users:toast.passwordSet"));
      } catch (err) {
        toast.error(i18next.t("users:toast.failedPassword"), err instanceof Error ? err.message : "");
        throw err;
      }
    },
    [http, invalidate],
  );

  const revokeSessions = useCallback(
    async (id: string) => {
      try {
        await http.post(`/v1/users/${id}/sessions/revoke`, {});
        toast.success(i18next.t("users:toast.sessionsRevoked"));
      } catch (err) {
        toast.error(i18next.t("users:toast.failedRevoke"), err instanceof Error ? err.message : "");
        throw err;
      }
    },
    [http],
  );

  return {
    users,
    loading,
    refresh: invalidate,
    createUser,
    updateUser,
    deleteUser,
    setPassword,
    revokeSessions,
  };
}
