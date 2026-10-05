export default interface ISendEmail {
  senderEmail: string;
  senderName: string;
  customerEmail: string;
  customerName: string;
  subject: string;
  textLetter?: { HTMLPart: string; TextPart: string };
  templateLetter?: {
    TemplateID: number;
    Variables?: Record<string, string | number>;
  };
}
