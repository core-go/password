package password

import "time"

func addSeconds(date time.Time, seconds int) time.Time {
	return date.Add(time.Second * time.Duration(seconds))
}

func compareDate(date1 time.Time, date2 time.Time) int {
	if date1.After(date2) {
		return 1
	} else if date1.Equal(date2) {
		return 0
	}
	return -1
}
