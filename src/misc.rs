use ark_ec::pairing::Pairing;
use ark_std::{rand::Rng, test_rng, UniformRand};

use crate::prover::User;

pub fn generate_random_balances(
    rng: &mut impl Rng,
    n: usize,
) -> Vec<u32> {
    // generates n random balances, greater or equal to 0
    assert!(n > 0 && n % 2 == 0, "n must be even and greater than 0");
    let mut balances: Vec<u32> = vec![];
    for i in 0..n {
        let balance = rng.gen_range(0..1000);
        balances.push(balance);
    }
    balances
}

pub fn generate_users(rng: &mut impl Rng, balances: &Vec<u32>) -> Vec<User> {
    let users = balances
        .iter()
        .map(|&balance| User {
            username: rng.gen_range(0..1000),
            balance,
            salt: rng.gen_range(0..1000),
        })
        .collect::<Vec<User>>();
    users
}

pub fn greet() {
    let art = "    
  $$$$$$\\   $$$$$$\\  $$$$$$$$\\ $$$$$$$$\\        $$$$$$\\  $$$$$$$$\\ $$\\   $$\\ 
 $$  __$$\\ $$  __$$\\ $$  _____|$$  _____|      $$  __$$\\ $$  _____|$$ |  $$ |
 $$ /  \\__|$$ /  $$ |$$ |      $$ |            $$ /  \\__|$$ |      \\$$\\ $$  |
 \\$$$$$$\\  $$$$$$$$ |$$$$$\\    $$$$$\\          $$ |      $$$$$\\     \\$$$$  / 
  \\____$$\\ $$  __$$ |$$  __|   $$  __|         $$ |      $$  __|    $$  $$<  
 $$\\   $$ |$$ |  $$ |$$ |      $$ |            $$ |  $$\\ $$ |      $$  /\\$$\\ 
 \\$$$$$$  |$$ |  $$ |$$ |      $$$$$$$$\\       \\$$$$$$  |$$$$$$$$\\ $$ /  $$ |
  \\______/ \\__|  \\__|\\__|      \\________|       \\______/ \\________|\\__|  \\__|
  
  ";
    println!("{}", art);
}
