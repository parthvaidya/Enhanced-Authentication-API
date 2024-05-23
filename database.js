const knex = require('knex')({
    client: 'sqlite3',
    connection: {
      filename: './userdata.db'
    },
    useNullAsDefault: true
  });

  knex.schema.hasTable('users').then(exists => {
    if (!exists) {
      return knex.schema.createTable('users', table => {
        table.increments('id').primary(); //id that increments
        table.string('name').notNullable();
        table.string('phoneNumber').unique().notNullable();
        table.string('email');
        table.string('password').notNullable();
        table.boolean('isAdmin').defaultTo(false); // Adding isAdmin field for admin privilege
        table.boolean('isPublic').defaultTo(true); // Adding isPublic field for profile privacy
      });
    }
  });






  module.exports = knex;