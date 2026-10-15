import Stripe from 'stripe';
import { json, error } from '@sveltejs/kit';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

// safe: the signature is checked on the raw body first
export async function POST({ request }) {
  const raw = await request.text();
  let event;
  try {
    event = stripe.webhooks.constructEvent(raw, request.headers.get('stripe-signature')!, process.env.STRIPE_WEBHOOK_SECRET!);
  } catch {
    throw error(400, 'bad signature');
  }
  if (event.type === 'checkout.session.completed') {
    /* ... */
  }
  return json({ received: true });
}
