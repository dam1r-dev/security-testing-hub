"use server";
// VULNERABLE Server Actions: public POST endpoints whose arguments come from the browser.
//  - deletePost  changes data and never checks who is calling (broken access control)
//  - searchPosts checks the session, then builds SQL from its argument (SQL injection)
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";

export async function deletePost(id: string) {
  await db.post.delete({ where: { id } });
}

export async function searchPosts(term: string) {
  await auth();
  return db.query("SELECT * FROM posts WHERE title LIKE '%" + term + "%'");
}
