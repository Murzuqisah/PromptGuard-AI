import { cn } from "@/lib/utils";
import { cva, type VariantProps } from "class-variance-authority";
import type { HTMLAttributes } from "react";

const badgeVariants = cva(
  "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-bold tracking-wide",
  {
    variants: {
      variant: {
        ALLOW: "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30",
        LOG: "bg-blue-500/15 text-blue-400 border border-blue-500/30",
        HUMAN_REVIEW: "bg-violet-500/15 text-violet-400 border border-violet-500/30",
        DENY: "bg-red-500/15 text-red-400 border border-red-500/30",
        default: "bg-surface-alt text-muted border border-border",
      },
    },
    defaultVariants: { variant: "default" },
  }
);

type BadgeProps = HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>;

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}
