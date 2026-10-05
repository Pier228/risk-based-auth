import ICreateConfirmation from './ICreateConfirmation';

export default interface ICreateAndSendConfirmation
  extends Omit<ICreateConfirmation, 'expiresIn'> {
  email: string;
  customerName: string;
  subject?: string;
  variables?: Record<string, string | number>;
  TemplateID?: number;
}
