import { Command } from "commander";

const program = new Command();

program
  .name("vuln-monkey")
  .description("AI-powered API security fuzzer")
  .version("0.1.0")
  .argument("[curl]", "curl command to fuzz")
  .option("--spec <url>", "OpenAPI/Swagger spec URL")
  .option("--model <model>", "LLM backend: claude or gemini", "claude")
  .option("--output <dir>", "Report output directory", "./reports")
  .option("--concurrency <n>", "Parallel requests", "5")
  .option("--timeout <ms>", "Request timeout", "10000")
  .option("--dry-run", "Generate payloads without firing", false)
  .action(async (curl, opts) => {
    if (!curl && !opts.spec) {
      program.error("Provide a curl command or --spec <url>");
    }
    console.log("vuln-monkey starting...", { curl: !!curl, spec: opts.spec });
    // Pipeline wired in Task 8
  });

program.parse();
