use ark_bn254::Fr;
use ark_ec::pairing::Pairing;
use ark_std::Zero;
use serde_json::Error;

#[derive(Debug, Clone)]
pub struct User {
    pub username: u32,
    pub balance: u32,
    pub salt: u32,
}

pub fn generate_witness<E: Pairing>(users: Vec<User>) -> Result<(Vec<E::ScalarField>, Vec<E::ScalarField>), Error> {
    let mut p_witness = Vec::new();
    let mut i_witness = Vec::new();
    
    // Implementing what's described here: https://vitalik.ca/general/2022/11/19/proof_of_solvency.html
    // Those will be the values of I(x)
    // For each user
    // 1. Push the username + salt to the p_witness
    // 2. Push the balance to the p_witness
    // 3. Create an array of 16 elements
    // 4. Take the user balance and assign it to the 14th index of the array
    // 5. Divide the balance by 2 and assign to the previous index of the array
    // 6. Repeat until it goes to 1
    // 7. Pad the rest of the array with 0s
    // 8. Assign the running total with an offset so that it sums to zero only if the total matches the declared total to the 15th index
    let mut accumlated_balance = 0;

    // range over users. Add to index i of p_wintess -> (username + salt) and to index i + 1 -> balance.
    for user in users.clone() {
        p_witness.push(E::ScalarField::from(user.username + user.salt));
        p_witness.push(E::ScalarField::from(user.balance));
        accumlated_balance += user.balance;
    }

    let avg = accumlated_balance / users.len() as u32;

    let mut running_total = 0;

    for user in users {
        let mut user_array = [E::ScalarField::zero(); 16];
        let mut balance = user.balance as u32;
        let mut index = 14;
        user_array[index] = E::ScalarField::from(balance);
        while balance > 0 {
            index -= 1;
            user_array[index] = E::ScalarField::from(balance / 2);
            balance /= 2;
        }

        running_total = running_total + user.balance as i32 - avg as i32;

        user_array[15] = E::ScalarField::from(running_total as u32);

        for i in 0..16 {
            i_witness.push(E::ScalarField::from(user_array[i]));
        }
    }

    // fill p_witness with zeroes to make it the same length as i_witness
    for _ in 0..i_witness.len() - p_witness.len() {
        p_witness.push(E::ScalarField::zero());
    }

    assert!(p_witness.len() == i_witness.len());

    Ok((p_witness, i_witness))
}
