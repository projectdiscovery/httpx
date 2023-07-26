package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx"
)

var mytoken = ""

func sessionHandler(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Check if token is already set
		if tokenCookie, err := c.Cookie("token"); err == nil {
			if tokenCookie.Value == mytoken {
				return next(c)
			}
		}
		// Check if token is passed as query parameter
		token := c.QueryParam("token")
		if token != mytoken || mytoken == "" {
			return c.String(http.StatusForbidden, "Invalid token")
		}
		c.SetCookie(&http.Cookie{
			Name:   "token",
			Value:  token,
			Path:   "/",
			MaxAge: 0, // Session cookie
		})
		return next(c)
	}
}

// SetupServer sets up the server for webui
func SetupServer(addr string) (chan<- []byte, error) {
	var err error
	// Initialize the database
	db, err = NewHttpxDB("")
	if err != nil {
		return nil, err
	}

	e := echo.New()

	e.StaticFS("/", echo.MustSubFS(httpx.WebUI, "web"))

	api := e.Group("/api/v1")

	api.GET("/data", func(c echo.Context) error {
		limit := c.QueryParam("limit")
		cursor := c.QueryParam("cursor")

		// Convert limit to integer
		n, err := strconv.Atoi(limit)
		if err != nil {
			return err
		}

		// Call GetWithCursor
		buff, lastKey, err := db.GetWithCursor(n, cursor)
		if err != nil {
			return err
		}
		c.Response().Header().Set("x-cursor", lastKey)
		c.Response().Write(buff.Bytes())
		c.Response().Flush()
		return nil
	})

	api.GET("/count", func(c echo.Context) error {
		c.String(http.StatusOK, strconv.Itoa(db.Count()))
		return nil
	})

	e.Use(sessionHandler)
	e.HideBanner = true

	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}

	go func() {
		gologger.Info().Msgf("Started Web Server at http://%s/?token=%v\n", addr, mytoken)
		if err := e.Start(addr); err != nil {
			gologger.Fatal().Msgf("Failed to start server: %s\n", err)
		}
	}()
	return dBChan, nil
}

// Close closes the database
func Close() error {
	close(dBChan)
	return db.Close()
}

func Wait() {
	wg.Wait()
}

func init() {
	value := uuid.New()
	mytoken = value.String()
}
