import { ConfirmationType, Prisma } from 'generated/prisma';

export default interface ICreateConfirmation {
  userId: string;
  type: ConfirmationType;
  expiresIn: number; // Milliseconds expected
  tx?: Prisma.TransactionClient;
}
