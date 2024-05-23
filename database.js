//connect to sqlitedb using knex 
const knex = require('knex')({
    client: 'sqlite3',
    connection: {
      filename: './userdata.db'
    },
    useNullAsDefault: true
  });

  //create table users
  knex.schema.hasTable('users').then(exists => {
    if (!exists) {
      return knex.schema.createTable('users', table => {
        table.increments('id').primary(); //id that increments
        table.string('name').notNullable();
        table.string('phoneNumber').unique().notNullable();
        table.string('email');
        table.string('password').notNullable();
        table.boolean('isAdmin').defaultTo(false); //  isAdmin field for admin privilege
        table.boolean('isPublic').defaultTo(true); //  isPublic field for profile privacy
      });
    }
  });






  module.exports = knex;