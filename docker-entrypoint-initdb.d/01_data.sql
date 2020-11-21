INSERT INTO users(login, password, roles)
VALUES
       ('admin', '$2a$10$ctPFhgJh.YIE21AA0OGl5er3p9f3XsAwkmTXnP2I7BxCpQbr1QAg2', '{"ADMIN", "USER"}'), -- у этого пользователя две роли (т.е. он и админ, и обычный юзер)
       ('user', '$2a$10$ctPFhgJh.YIE21AA0OGl5er3p9f3XsAwkmTXnP2I7BxCpQbr1QAg2', '{"USER"}');

INSERT INTO payments (senderId, amount)
VALUES (1, 1000000),
       (2, 2000000),
       (2, 3000000),
       (2, 4000000),
       (1, 5000000);


