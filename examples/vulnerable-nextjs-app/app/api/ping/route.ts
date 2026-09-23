// VULNERABLE: OS Command Injection (CWE-78) via a JSON request body.
import { exec } from "child_process";

export async function POST(request: Request) {
  const body = await request.json();
  const host = body.host;
  return new Promise((resolve) => {
    exec(`ping -c 1 ${host}`, (err, stdout) => {
      resolve(new Response(stdout));
    });
  });
}
