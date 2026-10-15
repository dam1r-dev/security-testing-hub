import { z } from 'zod';
import { createTRPCRouter, publicProcedure, protectedProcedure } from '../trpc';

export const postRouter = createTRPCRouter({
  // SQL injection: the validated input is still the caller's
  search: publicProcedure.input(z.object({ term: z.string() })).query(async ({ ctx, input }) => {
    return ctx.db.$queryRawUnsafe(`SELECT * FROM posts WHERE title LIKE '%${input.term}%'`);
  }),
  // changes data on a public procedure: nobody is checked
  remove: publicProcedure.input(z.object({ id: z.string() })).mutation(async ({ ctx, input }) => {
    return ctx.db.post.delete({ where: { id: input.id } });
  }),
  // signed in, but any user can change any post
  rename: protectedProcedure.input(z.object({ id: z.string(), title: z.string() })).mutation(async ({ ctx, input }) => {
    return ctx.db.post.update({ where: { id: input.id }, data: { title: input.title } });
  }),
  // signed in and scoped to the caller: fine
  mine: protectedProcedure.input(z.object({ id: z.string() })).mutation(async ({ ctx, input }) => {
    return ctx.db.post.deleteMany({ where: { id: input.id, authorId: ctx.session.user.id } });
  }),
});
