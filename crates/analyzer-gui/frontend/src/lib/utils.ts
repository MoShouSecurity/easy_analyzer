import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
export function basename(path: string) {
  return path.split(/[\\/]/).pop() || path;
}
export function bytes(value: number) {
  return value >= 1048576
    ? `${(value / 1048576).toFixed(1)} MiB`
    : value >= 1024
      ? `${(value / 1024).toFixed(1)} KiB`
      : `${value} B`;
}
export const number = (n: number) => new Intl.NumberFormat("zh-CN").format(n);
