package slice

func Filter[T any, S ~[]T](list S, f func(i T) bool) S {
	var res []T
	for _, i := range list {
		if f(i) {
			res = append(res, i)
		}
	}
	return res
}
