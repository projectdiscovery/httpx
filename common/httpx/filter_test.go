package httpx

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFilterCustomErrorPropagation(t *testing.T) {
	t.Run("error from callback is returned, not swallowed", func(t *testing.T) {
		expectedErr := errors.New("callback failure")
		callback := func(response *Response) (bool, error) {
			return true, expectedErr
		}
		filter := FilterCustom{CallBacks: []CustomCallback{callback}}
		ok, err := filter.Filter(&Response{})
		require.False(t, ok, "ok should be false when callback returns an error")
		require.ErrorIs(t, err, expectedErr, "error from callback should be propagated")
	})

	t.Run("error from callback with ok=false is returned", func(t *testing.T) {
		expectedErr := errors.New("callback failure")
		callback := func(response *Response) (bool, error) {
			return false, expectedErr
		}
		filter := FilterCustom{CallBacks: []CustomCallback{callback}}
		ok, err := filter.Filter(&Response{})
		require.False(t, ok)
		require.ErrorIs(t, err, expectedErr)
	})

	t.Run("first matching callback without error returns true", func(t *testing.T) {
		callbacks := []CustomCallback{
			func(response *Response) (bool, error) { return false, nil },
			func(response *Response) (bool, error) { return true, nil },
			func(response *Response) (bool, error) { return true, nil },
		}
		filter := FilterCustom{CallBacks: callbacks}
		ok, err := filter.Filter(&Response{})
		require.True(t, ok)
		require.NoError(t, err)
	})

	t.Run("error stops remaining callbacks", func(t *testing.T) {
		called := 0
		filter := FilterCustom{CallBacks: []CustomCallback{
			func(*Response) (bool, error) {
				called++
				return false, errors.New("fail")
			},
			func(*Response) (bool, error) {
				called++
				return true, nil
			},
		}}
		ok, err := filter.Filter(&Response{})
		require.False(t, ok)
		require.Error(t, err)
		require.Equal(t, 1, called)
	})

	t.Run("no callbacks match returns false with nil error", func(t *testing.T) {
		callbacks := []CustomCallback{
			func(response *Response) (bool, error) { return false, nil },
			func(response *Response) (bool, error) { return false, nil },
		}
		filter := FilterCustom{CallBacks: callbacks}
		ok, err := filter.Filter(&Response{})
		require.False(t, ok)
		require.NoError(t, err)
	})
}
