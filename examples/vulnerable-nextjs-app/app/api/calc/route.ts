// VULNERABLE: code injection (CWE-94). The expression from the JSON body is executed.
export async function POST(request: Request) {
  const body = await request.json();
  const result = new Function(`return ${body.expression}`)();
  return Response.json({ result });
}
