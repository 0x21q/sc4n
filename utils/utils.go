package utils

func Contains[T comparable](slice []T, x T) bool {
	for _, i := range slice {
		if i == x {
			return true
		}
	}
	return false
}
