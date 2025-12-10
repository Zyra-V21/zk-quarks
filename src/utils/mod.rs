//! Utility functions

pub mod msm;
pub mod batching;

use ark_std::log2;

/// Calculate the number of variables needed for 2^n evaluations
pub fn num_vars_for_size(size: usize) -> usize {
    log2(size) as usize
}

/// Check if a number is a power of 2
pub fn is_power_of_two(n: usize) -> bool {
    n > 0 && (n & (n - 1)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_num_vars() {
        assert_eq!(num_vars_for_size(1), 0);
        assert_eq!(num_vars_for_size(2), 1);
        assert_eq!(num_vars_for_size(4), 2);
        assert_eq!(num_vars_for_size(8), 3);
        assert_eq!(num_vars_for_size(1024), 10);
    }

    #[test]
    fn test_power_of_two() {
        assert!(is_power_of_two(1));
        assert!(is_power_of_two(2));
        assert!(is_power_of_two(4));
        assert!(is_power_of_two(1024));
        assert!(!is_power_of_two(0));
        assert!(!is_power_of_two(3));
        assert!(!is_power_of_two(100));
    }
}

