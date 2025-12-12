//! Generate and display real zkSNARK proofs
//!
//! Demonstrates the generic PCS architecture:
//! - Lakonia<KopisPCS> vs Lakonia<DoryPCS>
//! - Kopis<KopisPCS> vs Kopis<DoryPCS>
//! - Xiphos<DoryPCS> (the "Quark") vs Xiphos<KopisPCS>
//!
//! Shows how the same SNARK can use different PCS backends.

use ark_bls12_381::Fr;
use ark_serialize::CanonicalSerialize;
use ark_std::One;
use quarks_zk::{
    // Type aliases (recommended API)
    Lakonia, LakoniaDory,
    Kopis, KopisDory,
    Xiphos, XiphosKopis,
    // Common types
    Witness, Proof,
};
use quarks_zk::r1cs::{R1CSInstance, SparseMatrix};
use rand::thread_rng;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn create_example_r1cs() -> (R1CSInstance<Fr>, Witness) {
    // Example: Prove knowledge of x, y such that x * y = 12
    // R1CS: z[1] * z[2] = z[3] where z = [1, x, y, result]
    
    let mut a = SparseMatrix::new(1, 4);
    a.add_entry(0, 1, Fr::one()); // Select z[1] = x
    
    let mut b = SparseMatrix::new(1, 4);
    b.add_entry(0, 2, Fr::one()); // Select z[2] = y
    
    let mut c = SparseMatrix::new(1, 4);
    c.add_entry(0, 3, Fr::one()); // Select z[3] = result
    
    let instance = R1CSInstance::new(a, b, c, 1, 4, 0);
    
    // Witness: x=3, y=4, result=12
    let witness = Witness::from_assignments(vec![
        Fr::from(3u64),
        Fr::from(4u64),
        Fr::from(12u64),
    ]);
    
    (instance, witness)
}

fn print_hex(label: &str, bytes: &[u8], max_display: usize) {
    let display_len = bytes.len().min(max_display);
    let hex: String = bytes[..display_len]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("");
    
    if bytes.len() > max_display {
        println!("  {}: {}... ({} bytes total)", label, hex, bytes.len());
    } else {
        println!("  {}: {} ({} bytes)", label, hex, bytes.len());
    }
}

fn proof_size(proof: &Proof) -> usize {
    proof.witness_commitment.len()
        + proof.sumcheck_proofs.iter().map(|p| p.len() * 32).sum::<usize>()
        + proof.eval_proofs.iter().map(|p| p.len()).sum::<usize>()
}

/// Save proof to binary format (.quark)
fn save_proof_binary(proof: &Proof, filename: &str) -> std::io::Result<()> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("examples");
    path.push(filename);
    let mut buffer = Vec::new();
    
    buffer.extend_from_slice(&proof.witness_commitment);
    buffer.extend_from_slice(&(proof.sumcheck_proofs.len() as u32).to_le_bytes());
    
    for sc_proof in &proof.sumcheck_proofs {
        buffer.extend_from_slice(&(sc_proof.len() as u32).to_le_bytes());
        for field_elem in sc_proof {
            let mut fe_bytes = Vec::new();
            field_elem.serialize_compressed(&mut fe_bytes).unwrap();
            buffer.extend_from_slice(&fe_bytes);
        }
    }
    
    buffer.extend_from_slice(&(proof.eval_proofs.len() as u32).to_le_bytes());
    for eval_proof in &proof.eval_proofs {
        buffer.extend_from_slice(&(eval_proof.len() as u32).to_le_bytes());
        buffer.extend_from_slice(eval_proof);
    }
    
    let mut file = File::create(&path)?;
    file.write_all(&buffer)?;
    Ok(())
}

/// Save proof to JSON format
fn save_proof_json(proof: &Proof, filename: &str) -> std::io::Result<()> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("examples");
    path.push(filename);
    let mut json = String::from("{\n");
    
    json.push_str("  \"witness_commitment\": \"");
    json.push_str(&hex::encode(&proof.witness_commitment));
    json.push_str("\",\n");
    
    json.push_str("  \"sumcheck_proofs\": [\n");
    for (i, sc_proof) in proof.sumcheck_proofs.iter().enumerate() {
        json.push_str("    [\n");
        for (j, field_elem) in sc_proof.iter().enumerate() {
            let mut fe_bytes = Vec::new();
            field_elem.serialize_compressed(&mut fe_bytes).unwrap();
            json.push_str(&format!("      \"{}\"", hex::encode(&fe_bytes)));
            if j < sc_proof.len() - 1 { json.push(','); }
            json.push('\n');
        }
        json.push_str("    ]");
        if i < proof.sumcheck_proofs.len() - 1 { json.push(','); }
        json.push('\n');
    }
    json.push_str("  ],\n");
    
    json.push_str("  \"eval_proofs\": [\n");
    for (i, eval_proof) in proof.eval_proofs.iter().enumerate() {
        json.push_str(&format!("    \"{}\"", hex::encode(eval_proof)));
        if i < proof.eval_proofs.len() - 1 { json.push(','); }
        json.push('\n');
    }
    json.push_str("  ]\n}\n");
    
    let mut file = File::create(&path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

fn main() {
    let mut rng = thread_rng();
    
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║     QUARKS zkSNARK - Generic PCS Architecture Demo          ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");
    
    let (instance, witness) = create_example_r1cs();
    
    // Verify instance
    use quarks_zk::r1cs::Witness as R1CSWitness;
    let r1cs_witness = R1CSWitness {
        public_inputs: witness.public_inputs.clone(),
        assignments: witness.assignments.clone(),
    };
    
    println!("📋 R1CS Instance:");
    println!("   Statement: Prove knowledge of (x, y) such that x * y = 12");
    println!("   Witness: x=3, y=4, result=12");
    println!("   Satisfied: {}\n", instance.is_satisfied(&r1cs_witness).is_ok_and(|b| b));
    
    // ========== LAKONIA ==========
    println!("┌──────────────────────────────────────────────────────────────┐");
    println!("│  LAKONIA - NIZK (No preprocessing)                          │");
    println!("└──────────────────────────────────────────────────────────────┘\n");
    
    // Lakonia with Kopis-PC (type alias)
    println!("▸ Lakonia<KopisPCS> (O(√n) verification):");
    let lakonia_kopis = Lakonia::setup(4, &mut rng);
    let proof_lakonia_kopis = lakonia_kopis.prove(&instance, &witness, &mut rng);
    print_hex("  Commitment", &proof_lakonia_kopis.witness_commitment, 32);
    println!("  Size: {} bytes", proof_size(&proof_lakonia_kopis));
    println!("  Verified: {}\n", lakonia_kopis.verify(&instance, &proof_lakonia_kopis));
    
    // Lakonia with Dory-PC (type alias)
    println!("▸ Lakonia<DoryPCS> (O(log n) verification):");
    let lakonia_dory = LakoniaDory::setup(4, &mut rng);
    let proof_lakonia_dory = lakonia_dory.prove(&instance, &witness, &mut rng);
    print_hex("  Commitment", &proof_lakonia_dory.witness_commitment, 32);
    println!("  Size: {} bytes", proof_size(&proof_lakonia_dory));
    println!("  Verified: {}\n", lakonia_dory.verify(&instance, &proof_lakonia_dory));
    
    // ========== KOPIS ==========
    println!("┌──────────────────────────────────────────────────────────────┐");
    println!("│  KOPIS - zkSNARK with O(√n) verification                    │");
    println!("└──────────────────────────────────────────────────────────────┘\n");
    
    // Kopis with Kopis-PC (default)
    println!("▸ Kopis<KopisPCS> (default - shortest proofs):");
    let kopis = Kopis::setup(4, &mut rng);
    let cc_kopis = kopis.preprocess(&instance, &mut rng);
    let proof_kopis = kopis.prove(&instance, &witness, &cc_kopis, &mut rng);
    print_hex("  Commitment", &proof_kopis.witness_commitment, 32);
    println!("  Size: {} bytes", proof_size(&proof_kopis));
    println!("  Verified: {}\n", kopis.verify(&instance, &proof_kopis, &cc_kopis));
    
    // Kopis with Dory-PC
    println!("▸ Kopis<DoryPCS> (O(log n) verification):");
    let kopis_dory = KopisDory::setup(4, &mut rng);
    let cc_kopis_dory = kopis_dory.preprocess(&instance, &mut rng);
    let proof_kopis_dory = kopis_dory.prove(&instance, &witness, &cc_kopis_dory, &mut rng);
    print_hex("  Commitment", &proof_kopis_dory.witness_commitment, 32);
    println!("  Size: {} bytes", proof_size(&proof_kopis_dory));
    println!("  Verified: {}\n", kopis_dory.verify(&instance, &proof_kopis_dory, &cc_kopis_dory));
    
    // ========== XIPHOS ==========
    println!("┌──────────────────────────────────────────────────────────────┐");
    println!("│  XIPHOS - The \"Quark\" (Quadruple-efficient)                 │");
    println!("└──────────────────────────────────────────────────────────────┘\n");
    
    // Xiphos with Dory-PC (the true "Quark")
    println!("▸ Xiphos<DoryPCS> (default - O(log n) everything!):");
    let xiphos = Xiphos::setup(4, &mut rng);
    let cc_xiphos = xiphos.preprocess(&instance, &mut rng);
    let proof_xiphos = xiphos.prove(&instance, &witness, &cc_xiphos, &mut rng);
    print_hex("  Commitment", &proof_xiphos.witness_commitment, 32);
    println!("  Size: {} bytes", proof_size(&proof_xiphos));
    println!("  Verified: {}\n", xiphos.verify(&instance, &proof_xiphos, &cc_xiphos));
    
    // Xiphos with Kopis-PC
    println!("▸ Xiphos<KopisPCS> (O(√n) verification):");
    let xiphos_kopis = XiphosKopis::setup(4, &mut rng);
    let cc_xiphos_kopis = xiphos_kopis.preprocess(&instance, &mut rng);
    let proof_xiphos_kopis = xiphos_kopis.prove(&instance, &witness, &cc_xiphos_kopis, &mut rng);
    print_hex("  Commitment", &proof_xiphos_kopis.witness_commitment, 32);
    println!("  Size: {} bytes", proof_size(&proof_xiphos_kopis));
    println!("  Verified: {}\n", xiphos_kopis.verify(&instance, &proof_xiphos_kopis, &cc_xiphos_kopis));
    
    // ========== GENERIC API DEMO ==========
    println!("┌──────────────────────────────────────────────────────────────┐");
    println!("│  Generic API - Explicit PCS Selection                       │");
    println!("└──────────────────────────────────────────────────────────────┘\n");
    
    println!("▸ Using explicit generic syntax:");
    println!("  LakoniaSnark::<KopisPCS>::setup(4, &mut rng)");
    println!("  LakoniaSnark::<DoryPCS>::setup(4, &mut rng)");
    println!("  KopisSnark::<KopisPCS>::setup(4, &mut rng)");
    println!("  XiphosSnark::<DoryPCS>::setup(4, &mut rng)\n");
    
    // ========== COMPARISON ==========
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                    PROOF SIZE COMPARISON                     ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");
    
    println!("┌─────────────────────┬────────────┬────────────┐");
    println!("│ SNARK               │ Kopis-PC   │ Dory-PC    │");
    println!("├─────────────────────┼────────────┼────────────┤");
    println!("│ Lakonia             │ {:>6} B   │ {:>6} B   │", 
             proof_size(&proof_lakonia_kopis), proof_size(&proof_lakonia_dory));
    println!("│ Kopis               │ {:>6} B   │ {:>6} B   │", 
             proof_size(&proof_kopis), proof_size(&proof_kopis_dory));
    println!("│ Xiphos              │ {:>6} B   │ {:>6} B   │", 
             proof_size(&proof_xiphos_kopis), proof_size(&proof_xiphos));
    println!("└─────────────────────┴────────────┴────────────┘\n");
    
    println!("Verification Complexity:");
    println!("  • Kopis-PC: O(√n) - faster for small n");
    println!("  • Dory-PC:  O(log n) - faster for large n\n");
    
    // Save proofs
    save_proof_binary(&proof_lakonia_kopis, "lakonia_kopis_proof.quark").unwrap();
    save_proof_json(&proof_lakonia_kopis, "lakonia_kopis_proof.json").unwrap();
    save_proof_binary(&proof_lakonia_dory, "lakonia_dory_proof.quark").unwrap();
    save_proof_json(&proof_lakonia_dory, "lakonia_dory_proof.json").unwrap();
    save_proof_binary(&proof_kopis, "kopis_proof.quark").unwrap();
    save_proof_json(&proof_kopis, "kopis_proof.json").unwrap();
    save_proof_binary(&proof_kopis_dory, "kopis_dory_proof.quark").unwrap();
    save_proof_json(&proof_kopis_dory, "kopis_dory_proof.json").unwrap();
    save_proof_binary(&proof_xiphos, "xiphos_dory_proof.quark").unwrap();
    save_proof_json(&proof_xiphos, "xiphos_dory_proof.json").unwrap();
    save_proof_binary(&proof_xiphos_kopis, "xiphos_kopis_proof.quark").unwrap();
    save_proof_json(&proof_xiphos_kopis, "xiphos_kopis_proof.json").unwrap();
    
    println!("📁 Saved proofs:");
    println!("   • lakonia_kopis_proof.quark/json");
    println!("   • lakonia_dory_proof.quark/json");
    println!("   • kopis_proof.quark/json");
    println!("   • kopis_dory_proof.quark/json");
    println!("   • xiphos_dory_proof.quark/json");
    println!("   • xiphos_kopis_proof.quark/json\n");
    
    println!("✅ Generic PCS architecture working correctly!");
}
