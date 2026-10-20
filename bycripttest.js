const bcrypt = require('bcrypt');

async function test() {
  const hash = await bcrypt.hash('password123', 10);
  console.log(hash);

  const match = await bcrypt.compare('password123', hash);
  console.log('Match:', match);
}

test();
