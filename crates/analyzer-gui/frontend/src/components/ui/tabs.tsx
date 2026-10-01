import * as TabsPrimitive from "@radix-ui/react-tabs";
import type { ReactNode } from "react";
export function Tabs({
  value,
  onChange,
  items,
  children,
}: {
  value: string;
  onChange: (v: string) => void;
  items: { value: string; label: string }[];
  children?: ReactNode;
}) {
  return (
    <TabsPrimitive.Root
      value={value}
      onValueChange={onChange}
      className="tabs-root"
    >
      <TabsPrimitive.List className="tabs-list">
        {items.map((i) => (
          <TabsPrimitive.Trigger
            key={i.value}
            value={i.value}
            className="tabs-trigger"
          >
            {i.label}
          </TabsPrimitive.Trigger>
        ))}
      </TabsPrimitive.List>
      {children}
    </TabsPrimitive.Root>
  );
}
