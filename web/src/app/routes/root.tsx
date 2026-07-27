import { Outlet, createRootRoute } from "@tanstack/react-router";

export const Route = createRootRoute({
  component: RootLayout,
});

function RootLayout() {
  return (
    <div className="flex min-h-dvh flex-col">
      <a className="snowman-skip-link" href="#snowman-main-content">
        Skip to main content
      </a>
      <main
        className="flex flex-1 flex-col"
        id="snowman-main-content"
        tabIndex={-1}
      >
        <Outlet />
      </main>
    </div>
  );
}
