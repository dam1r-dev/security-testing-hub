import { json } from '@sveltejs/kit';
import { prisma } from '$lib/db';

// anyone can POST a fake "checkout.session.completed": no signature is checked
export async function POST({ request }) {
  const event = await request.json();
  if (event.type === 'checkout.session.completed') {
    await prisma.user.update({ where: { email: event.data.object.customer_email }, data: { plan: 'pro' } });
  }
  return json({ received: true });
}
