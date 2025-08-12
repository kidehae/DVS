import http from "http";
import { fileURLToPath } from 'url';
import { dirname, join, extname } from "path";
import fs from "fs";
import { WebSocketServer } from "ws";
import { runCodeScan } from "../scanners/code_scanner.js";
import chalk from "chalk";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export async function startDashboard(port?: number) {
  // Pick a port automatically if not given
  const actualPort = port || await findAvailablePort(5713);

  const server = http.createServer((req, res) => {
    let filePath = "";
    if (req.url === "/" || req.url === "/dashboard") {
      filePath = join(__dirname, "../templates/dashboard.html");
    } else if (req.url?.endsWith(".css")) {
      filePath = join(__dirname, "../templates/styles.css");
    }

    if (filePath && fs.existsSync(filePath)) {
      const ext = extname(filePath);
      res.setHeader("Content-Type", ext === ".css" ? "text/css" : "text/html");
      fs.createReadStream(filePath).pipe(res);
    } else {
      res.writeHead(404);
      res.end("Not Found");
    }
  });

  const wss = new WebSocketServer({ server });

  // When scanning finishes, broadcast results
  async function sendScanResults() {
    const results = {
      reflective: await runCodeScan(),
      stored: [], // example placeholder
      dom: []
    };
    wss.clients.forEach(client => {
      if (client.readyState === client.OPEN) {
        client.send(JSON.stringify({ type: "update", results }));
      }
    });
  }

  // Example: start scan when first client connects
  wss.on("connection", () => {
    sendScanResults();
  });

  server.listen(actualPort, () => {
    const url = `http://localhost:${actualPort}`;
    console.log(chalk.blue(`Dashboard available at: ${url}`));
    try {
      require("open")(url);
    } catch {
      console.log("Open the link in your browser.");
    }
  });
}

async function findAvailablePort(startPort: number): Promise<number> {
  const net = await import("net");
  function checkPort(port: number) {
    return new Promise<boolean>((resolve) => {
      const tester = net.createServer()
        .once("error", () => resolve(false))
        .once("listening", () => tester.once("close", () => resolve(true)).close())
        .listen(port);
    });
  }

  let port = startPort;
  while (!(await checkPort(port))) port++;
  return port;
}
