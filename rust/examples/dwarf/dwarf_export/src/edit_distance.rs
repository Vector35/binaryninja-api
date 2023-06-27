pub(crate) fn distance(a: &str, b: &str) -> usize {
    if a == b {
        return 0;
    }
    match (a.chars().count(), b.chars().count()) {
        (0, b) => return b,
        (a, 0) => return a,
        // (a_len, b_len) if a_len < b_len => return distance(b, a),
        _ => (),
    }

    let mut result = 0;
    let mut cache: Vec<usize> = (1..a.chars().count() + 1).collect();

    for (index_b, char_b) in b.chars().enumerate() {
        result = index_b;
        let mut distance_a = index_b;

        for (index_a, char_a) in a.chars().enumerate() {
            let distance_b = if char_a == char_b {
                distance_a
            } else {
                distance_a + 1
            };

            distance_a = cache[index_a];

            result = if distance_a > result {
                if distance_b > result {
                    result + 1
                } else {
                    distance_b
                }
            } else if distance_b > distance_a {
                distance_a + 1
            } else {
                distance_b
            };

            cache[index_a] = result;
        }
    }
    result
}
