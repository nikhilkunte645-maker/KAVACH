import { AnimatedGrid } from "@/components/ui/animated-grid";

export default function AnimatedGridDemo() {
  return (
    <div className="relative h-screen w-full overflow-hidden bg-background">
      <AnimatedGrid />
      <div className="relative z-10 flex h-full w-full flex-col items-center justify-center gap-2 text-center">
        <h1 className="text-4xl font-semibold tracking-tight text-foreground">
          Build faster.
        </h1>
        <p className="max-w-md text-muted-foreground">
          A CSS-only animated grid backdrop for heroes and section backgrounds.
        </p>
      </div>
    </div>
  );
}
