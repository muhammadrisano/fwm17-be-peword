const pool = require('../config/db')
const create = ({id, email, password, role}) => {
  return new Promise((resolve, reject) => {
    pool.query('INSERT INTO users(id, email, password, role)VALUES($1, $2, $3, $4)', [id, email, password, role], (error, result) => {
      if (!error) {
        resolve(result)
      } else {
        reject(error)
      }
    })
  })
}
const findByEmail = (email, {relation} = {relation: ''}) => {
  // console.log(relation);
  return new Promise((resolve, reject) => {
    pool.query(
      `SELECT users.id AS user_id, users.email, users.role, users.password ${relation ? `, ${relation}.*`:''} FROM users ${relation ? ` JOIN ${relation} ON users.id = user_id`: ''} WHERE email = $1 `,
      [email],
      (error, result) => {
        if (!error) {
          resolve(result);
        } else {
          reject(error);
        }
      }
    );
  });
};
const updateEmail = ({email}, id) =>{
  return pool.query(
    "UPDATE users SET email = $1 WHERE id = $2",
    [email, id]
  );
}
const deleteOne = (id)=>{
  return pool.query(
    "DELETE FROM users WHERE id = $1 RETURNING * ",
    [id]
  );
}
module.exports = {
  create,
  findByEmail,
  updateEmail,
  deleteOne
}