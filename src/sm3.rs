fn sm3_ff_j(x: u32, y: u32, z: u32, j: u32) -> u32 {
    let mut ret = 0;
    if j < 16 {
        ret = x ^ y ^ z;
    } else if 16 <= j && j < 64 {
        ret = (x & y) | (x & z) | (y & z);
    }
    ret
}

fn sm3_gg_j(x: u32, y: u32, z: u32, j: u32) -> u32 {
    let mut ret = 0;
    if j < 16 {
        ret = x ^ y ^ z;
    } else if 16 <= j && j < 64 {
        ret = (x & y) | (!x & z)
    }
    ret
}

fn sm3_p_0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

fn sm3_p_1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

fn sm3_cf(v_i: &Vec<u32>, b_i: &Vec<u32>) -> Vec<u32> {
    let t_j: Vec<u32> = vec![
    2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
    2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
    2043430169, 2043430169, 2043430169, 2043430169, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
    2055708042, 2055708042, 2055708042, 2055708042
    ];
    let mut w: Vec<u32> = Vec::new();
    for i in 0..16 {
        let mut weight = 0x1000000;
        let mut data: u32 = 0;
        for k in (i * 4)..((i + 1) * 4) {
            data = data.wrapping_add(b_i[k] * weight);
            weight /= 0x100;
        }
        w.push(data);
    }
    for j in 16..68 {
        w.push(0);
        w[j] = sm3_p_1(w[j - 16] ^ w[j - 9] ^ w[j - 3].rotate_left(15)) ^ w[j - 13].rotate_left(7) ^ w[j - 6];
    }
    let mut w_1: Vec<u32> = Vec::new();
    for j in 0..64 {
        w_1.push(0);
        w_1[j] = w[j] ^ w[j + 4];
    }
    let mut a = v_i[0];
    let mut b = v_i[1];
    let mut c = v_i[2];
    let mut d = v_i[3];
    let mut e = v_i[4];
    let mut f = v_i[5];
    let mut g = v_i[6];
    let mut h = v_i[7];
    for j in 0..64 {
        let ss_1 = ((a.rotate_left(12).wrapping_add(e).wrapping_add(t_j[j].rotate_left(j as u32))) & 0xffffffff).rotate_left(7);        
        let ss_2 = ss_1 ^ a.rotate_left(12);
        let tt_1 = (sm3_ff_j(a, b, c, j as u32).wrapping_add(d).wrapping_add(ss_2).wrapping_add(w_1[j])) & 0xffffffff;
        let tt_2 = (sm3_gg_j(e, f, g, j as u32).wrapping_add(h).wrapping_add(ss_1).wrapping_add(w[j])) & 0xffffffff;
        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt_1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = sm3_p_0(tt_2);
        a = a & 0xFFFFFFFF;
        b = b & 0xFFFFFFFF;
        c = c & 0xFFFFFFFF;
        d = d & 0xFFFFFFFF;
        e = e & 0xFFFFFFFF;
        f = f & 0xFFFFFFFF;
        g = g & 0xFFFFFFFF;
        h = h & 0xFFFFFFFF;
    }
    let v_j: Vec<u32> = vec![a, b, c, d, e, f, g, h];
    let mut cf: Vec<u32> = Vec::new();
    for i in 0..8 {
        cf.push(v_j[i] ^ v_i[i]);
    }
    cf
}

pub fn sm3_hash(msg: &[u8]) -> String {
    let iv: Vec<u32> = vec![
    1937774191, 1226093241, 388252375, 3666478592,
    2842636476, 372324522, 3817729613, 2969243214,
    ];
    let mut msg = msg.to_vec();
    let len1 = msg.len();
    let mut reserve1 = len1 % 64;
    msg.push(0x80);
    reserve1 += 1;
    let mut range_end = 56;
    if reserve1 > range_end {
        range_end += 64;
    }
    for _ in reserve1..range_end {
        msg.push(0x00);
    }
    let mut bit_length: usize = len1 * 8;
    let mut bit_length_str: Vec<usize> = vec![bit_length % 0x100]; 
    for _ in 0..7 {
        bit_length /= 0x100;
        bit_length_str.push(bit_length % 0x100);
    }
    for i in 0..8 {
        msg.push(bit_length_str[7 - i] as u8);
    }
    let group_count: usize = (((msg.len() as f32) / 64.0).round()) as usize;
    let mut b: Vec<Vec<u32>> = Vec::new();
    for i in 0..group_count {
        b.push(msg[(i * 64)..((i + 1) * 64)].iter().map(|x| x.to_be() as u32).collect());
    }
    let mut v: Vec<Vec<u32>> = Vec::new();
    v.push(iv);
    for i in 0..group_count {
        v.push(sm3_cf(&v[i], &b[i]));
    }
    let y = &v[group_count - 1 + 1];
    let mut result = "".to_string();
    for i in y {
        result += &format!("{:08x}", i);
    }
    result
}

pub fn sm3_hash_file(input_file: &str) -> String {
    let input_file = std::path::Path::new(input_file);
    let input_data = std::fs::read(input_file).unwrap();
    sm3_hash(&input_data)
}

pub fn sm3_hash_string(msg_str: &str) -> String {
    let msg = msg_str.as_bytes();
    sm3_hash(msg)
}

pub fn paste_str(v: Vec<&str>) -> Vec<String> {
    let mut result = Vec::new();
    let s = "BRWS_".to_string();
    for i in v {
        result.push(s.clone() + i);
    }
    result
}

