package gin

import (
	"net/http"
	"todo-app/domain"
	"todo-app/pkg/clients"
	"todo-app/pkg/tokenprovider"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type UserService interface {
	Register(data *domain.UserCreate) error
	Login(data *domain.UserLogin) (tokenprovider.Token, error)
	UpdateUser(data *domain.UserUpdate, id uuid.UUID) error
	GetUserByID(id uuid.UUID) (*domain.User, error)
}

type userHandler struct {
	userService UserService
}

func NewUserHandler(apiVersion *gin.RouterGroup, svc UserService, authMiddleware func(c *gin.Context)) {
	userHandler := &userHandler{
		userService: svc,
	}

	users := apiVersion.Group("/users")
	users.POST("/register", userHandler.RegisterUserHandler)
	users.POST("/login", userHandler.LoginHandler)
	users.GET("/profile", authMiddleware, userHandler.getUserByIDHandler)
	users.PATCH("/", authMiddleware, userHandler.updateUserHandler)
}

// @Summary      Register a new user
// @Description  This endpoint registers a new user in the system.
// @Tags         Users
// @Accept       json
// @Produce      json
// @Param        user  body      domain.UserCreate    true   "User creation payload"
// @Success      200   {object}  clients.SuccessRes   "User successfully registered"
// @Failure      400   {object}  clients.AppError     "Bad Request"
// @Router       /users/register [post]
func (h *userHandler) RegisterUserHandler(c *gin.Context) {
	var data domain.UserCreate

	if err := c.ShouldBind(&data); err != nil {
		c.JSON(http.StatusBadRequest, clients.ErrInvalidRequest(err))

		return
	}

	if err := h.userService.Register(&data); err != nil {
		c.JSON(http.StatusBadRequest, err)

		return
	}

	c.JSON(http.StatusOK, clients.SimpleSuccessResponse(data.ID))
}

// @Summary      Login user
// @Description  This endpoint logs a user into the system and returns a token.
// @Tags         Users
// @Accept       json
// @Produce      json
// @Param        user  body      domain.UserLogin     true   "User login payload"
// @Success      200   {object}  clients.SuccessRes   "Token successfully generated"
// @Failure      400   {object}  clients.AppError     "Invalid credentials"
// @Router       /users/login [post]
func (h *userHandler) LoginHandler(c *gin.Context) {
	var data domain.UserLogin

	if err := c.ShouldBind(&data); err != nil {
		c.JSON(http.StatusBadRequest, clients.ErrInvalidRequest(err))

		return
	}

	token, err := h.userService.Login(&data)
	if err != nil {
		c.JSON(http.StatusBadRequest, err)

		return
	}

	c.JSON(http.StatusOK, clients.SimpleSuccessResponse(token))
}

// @Summary      update user
// @Description  This endpoint logs a user into the system and returns a token.
// @Tags         Users
// @Accept       json
// @Produce      json
// @Param        user  body      domain.UserUpdate     true   "User login payload"
// @Success      200   {object}  clients.SuccessRes   "Token successfully generated"
// @Failure      400   {object}  clients.AppError     "Invalid credentials"
// @Router       /users [patch]
// @Security     BearerAuth
func (h *userHandler) updateUserHandler(c *gin.Context) {
	requester := c.MustGet(clients.CurrentUser).(clients.Requester)
	item := domain.UserUpdate{}
	if err := c.ShouldBind(&item); err != nil {
		c.JSON(http.StatusBadRequest, clients.ErrInvalidRequest(err))

		return
	}
	h.userService.UpdateUser(&item, requester.GetUserID())
	c.JSON(http.StatusOK, clients.SimpleSuccessResponse(requester.GetUserID()))
}

// @Summary      Get user by ID
// @Description  Retrieve detailed information of a user based on their unique UUID.
// @Tags         Users
// @Accept       json
// @Produce      json
// @Success      200   {object}  clients.SuccessRes   "User successfully retrieved"
// @Failure      400   {object}  clients.AppError     "Invalid user ID or user not found"
// @Router       /users/profile [get]
// @Security     BearerAuth
func (h *userHandler) getUserByIDHandler(c *gin.Context) {
	requester := c.MustGet(clients.CurrentUser).(clients.Requester)
	item := domain.UserUpdate{}
	if err := c.ShouldBind(&item); err != nil {
		c.JSON(http.StatusBadRequest, clients.ErrInvalidRequest(err))

		return
	}
	user, err := h.userService.GetUserByID(requester.GetUserID())
	if err != nil {
		c.JSON(http.StatusBadRequest, err)

		return
	}

	c.JSON(http.StatusOK, clients.SimpleSuccessResponse(user))
}
