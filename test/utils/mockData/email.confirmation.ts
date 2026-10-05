export const mockEmailConfirmation = {
  invalid: [
    { token: '', confirmationId: crypto.randomUUID() }, // empty token
    { token: '321', confirmationId: crypto.randomUUID() }, // token must be 6 characters
    { token: 3213123213, confirmationId: crypto.randomUUID() }, // token must be string
    { token: '123456', confirmationId: '' }, // empty confirmationId
    { token: '123456', confirmationId: 123123 }, // invalid uuid & must be string
    { token: '123456', confirmationId: '123-321' }, // invalid uuid
  ],
};
