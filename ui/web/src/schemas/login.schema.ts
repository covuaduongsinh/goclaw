import { z } from "zod";

export const tokenFormSchema = z.object({
  userId: z.string().min(1, "Required"),
  token: z.string().min(1, "Required"),
});

export const passwordFormSchema = z.object({
  email: z.string().min(1, "Required").email("Invalid email address"),
  password: z.string().min(1, "Required"),
});

// Minimum length matches crypto.MinPasswordLength on the server. The server
// re-checks it, so this only saves a round trip.
export const changePasswordSchema = z
  .object({
    currentPassword: z.string().min(1, "Required"),
    newPassword: z.string().min(12, "Password must be at least 12 characters"),
    confirmPassword: z.string().min(1, "Required"),
  })
  .refine((data) => data.newPassword === data.confirmPassword, {
    message: "Passwords do not match",
    path: ["confirmPassword"],
  });

export const pairingFormSchema = z.object({
  userId: z.string().min(1, "Required"),
});

export type TokenFormData = z.infer<typeof tokenFormSchema>;
export type PasswordFormData = z.infer<typeof passwordFormSchema>;
export type ChangePasswordData = z.infer<typeof changePasswordSchema>;
export type PairingFormData = z.infer<typeof pairingFormSchema>;
