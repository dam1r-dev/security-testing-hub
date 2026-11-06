// Deliberately vulnerable gin handlers: a fixture for the scanner's tests. Do not deploy.
package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type Comment struct {
	Author string `json:"author"`
	Body   string `json:"body"`
}

// SQL injection through GORM: the sort column and a filter come from the query string.
func listPosts(c *gin.Context) {
	sort := c.Query("sort")
	author := c.Query("author")
	var posts []Post
	gdb.Where("author = '" + author + "'").Order(sort).Find(&posts)
	c.JSON(http.StatusOK, posts)
}

// SQL injection: a field of the bound JSON body.
func addComment(c *gin.Context) {
	var in Comment
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad body"})
		return
	}
	db.Exec("INSERT INTO comments (author, body) VALUES ('" + in.Author + "', '" + in.Body + "')")
	c.Status(http.StatusCreated)
}

// Path traversal: the uploaded file name decides where it is written.
func upload(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.String(http.StatusBadRequest, "no file")
		return
	}
	c.SaveUploadedFile(file, "./uploads/"+file.Filename)
	c.String(http.StatusOK, "saved")
}

// Open redirect.
func logout(c *gin.Context) {
	c.Redirect(http.StatusFound, c.Query("to"))
}

// Safe: the id is parsed to a number first.
func getPost(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	db.QueryRow("SELECT title FROM posts WHERE id = " + fmt.Sprint(id))
}

// CORS: every site may call the API with cookies.
func corsConfig() cors.Config {
	return cors.Config{AllowAllOrigins: true, AllowCredentials: true}
}
