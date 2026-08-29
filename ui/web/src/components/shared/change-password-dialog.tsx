import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useHttp } from "@/hooks/use-ws";
import { toast } from "@/stores/use-toast-store";
import { changePasswordSchema, type ChangePasswordData } from "@/schemas/login.schema";

interface ChangePasswordDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /**
   * Set when the server flagged the account as must_change_password. The
   * dialog then cannot be dismissed, because the account is not usable until
   * the administrator-chosen password is replaced.
   */
  forced?: boolean;
}

export function ChangePasswordDialog({ open, onOpenChange, forced }: ChangePasswordDialogProps) {
  const { t } = useTranslation("users");
  const { t: tc } = useTranslation("common");
  const http = useHttp();
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<ChangePasswordData>({
    resolver: zodResolver(changePasswordSchema),
    defaultValues: { currentPassword: "", newPassword: "", confirmPassword: "" },
  });

  const onValid = async (data: ChangePasswordData) => {
    setSubmitting(true);
    setError(null);
    try {
      // The server revokes every other session on success, so other devices
      // are signed out; this one keeps working.
      await http.post("/v1/auth/change-password", {
        current_password: data.currentPassword,
        new_password: data.newPassword,
      });
      toast.success(t("changePassword.success"));
      reset();
      onOpenChange(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (forced && !next) return;
        onOpenChange(next);
      }}
    >
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("changePassword.title")}</DialogTitle>
          <DialogDescription>
            {forced ? t("changePassword.forcedDescription") : t("changePassword.description")}
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit(onValid)} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="current-password">{t("changePassword.current")}</Label>
            <Input
              id="current-password"
              type="password"
              autoComplete="current-password"
              {...register("currentPassword")}
              className="text-base md:text-sm"
              disabled={submitting}
            />
            {errors.currentPassword && (
              <p className="text-xs text-destructive">{errors.currentPassword.message}</p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="new-password">{t("changePassword.new")}</Label>
            <Input
              id="new-password"
              type="password"
              autoComplete="new-password"
              {...register("newPassword")}
              className="text-base md:text-sm"
              disabled={submitting}
            />
            {errors.newPassword && (
              <p className="text-xs text-destructive">{errors.newPassword.message}</p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="confirm-password">{t("changePassword.confirm")}</Label>
            <Input
              id="confirm-password"
              type="password"
              autoComplete="new-password"
              {...register("confirmPassword")}
              className="text-base md:text-sm"
              disabled={submitting}
            />
            {errors.confirmPassword && (
              <p className="text-xs text-destructive">{errors.confirmPassword.message}</p>
            )}
          </div>

          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}

          <DialogFooter>
            {!forced && (
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
                disabled={submitting}
              >
                {tc("cancel")}
              </Button>
            )}
            <Button type="submit" disabled={submitting}>
              {submitting ? tc("saving") : t("changePassword.submit")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
