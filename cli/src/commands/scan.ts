import { Command } from "commander";
import { startDashboard } from "../utils/dashboard_server.js";

export const scanCommand = new Command("scan")
  .description("Run vulnerability scans and open dashboard")
  .option("--port <port>", "Port for dashboard")
  .action(async (options) => {
    const port = options.port ? parseInt(options.port, 10) : undefined;
    await startDashboard(port);
  });
