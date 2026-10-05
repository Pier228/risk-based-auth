const mockUsers = {
  validSignUpParams: [
    {
      email: 'example@gmail.com',
      password: 'password123',
      name: 'Pier',
      surname: 'Clinton',
    },
    {
      email: 'test@gmail.com',
      password: 'anotherPassword123',
      name: 'Emily',
      surname: 'Bells',
    },
    {
      email: 'exampleEmail123@online.ua',
      password: 'P@ssw0rd!',
      name: 'Olivia',
      surname: 'Parker',
    },
    {
      email: 'testEmail@online.ud',
      password: 'p4ssW0rd!',
      name: 'Nick',
      surname: 'Porterro',
    },
    {
      email: 'validemail@gmail.com',
      password: 'ValidPassword123',
      name: 'Popoa',
      surname: 'Muzini',
    },
    {
      email: 'VALIDemail@gmail.com',
      password: 'validpassword123',
      name: 'Sakura',
      surname: 'Uchiha',
    },
    {
      email: 'validemail@online.ua',
      password: 'valid password 123',
      name: 'Hinata',
      surname: 'Jojios',
    },
  ],
  signUpInvalidParams: [
    {
      email: '',
      password: 'weakPassword123',
      name: 'Pier',
      surname: 'Clinton',
    }, // email is empty
    {
      email: 'a',
      password: 'weakPassword123',
      name: 'Pier',
      surname: 'Clinton',
    }, // invalid email
    {
      email: 'example@gmail.com',
      password: '',
      name: 'Pier',
      surname: 'Clinton',
    }, // empty password
    {
      email: 'test@gmail.com',
      password: '123321',
      name: 'Pier',
      surname: 'Clinton',
    }, // Password has a length of less than 8 characters
    {
      email: 'example@gmail.com',
      password:
        'veryLongPasswordThatIsOverTheLimitOf30CharactersButThisCouldBeValidIfTrimmedDown',
      name: 'Pier',
      surname: 'Clinton',
    }, // Password is over the maximum allowed length
    {
      email: 'example1@online.ua',
      password: 'weakPassword123',
      name: 'a',
      surname: 'Clinton',
    }, // name has a length of less than 2 characters
    {
      email: 'example13@online.ua',
      password: 'weakPassword123',
      name: '',
      surname: 'Clinton',
    }, // name field is empty
    {
      email: 'example2@online.ua',
      password: 'weakPassword123',
      name: 'superLongUserNameAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      surname: 'Clinton',
    }, // Name is over the maximum allowed length
    {
      email: 'test3123@online.ua',
      password: 'weakPassword123',
      name: 'pier',
      surname: 'a',
    }, // Surname has a length of less than 2 characters
    {
      email: 'example1310@gmail.com',
      password: 'weakPassword123',
      name: 'Pier',
      surname: '',
    }, // Surname field is empty
    {
      email: 'example23521@online.ua',
      password: 'weakPassword123',
      name: 'Pier',
      surname: 'superLongUserSurnameAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    }, // Surname is over the maximum allowed length
  ],
  signInInvalidParams: [
    { email: '', password: 'somePassword123' }, // empty email
    { email: 'Randomemail', password: 'somePassword123' }, // invalid email
    { email: 312123123, password: 'asfasgas123asd2' }, // invalid email
    { email: 'example12938@gmail.com', password: '' }, // empty password
  ],
};

export default mockUsers;
