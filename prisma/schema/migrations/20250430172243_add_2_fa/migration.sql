/*
  Warnings:

  - You are about to drop the column `emailConfirmed` on the `users` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "tokens" ADD COLUMN     "two_factor_user_agent" TEXT;

-- AlterTable
ALTER TABLE "users" DROP COLUMN "emailConfirmed",
ADD COLUMN     "email_confirmed" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "two_factor_auth_enabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "two_factor_country" TEXT;
