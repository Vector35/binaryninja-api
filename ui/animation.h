#pragma once

#include "clickablelabel.h"
#include <deque>
#include <unordered_map>
#include <QObject>
#include <QVariantAnimation>
#include <QMetaObject>
#include <QPropertyAnimation>
#include <QLabel>
#include <QListView>
#include <QTreeView>
#include <QScrollBar>
#include <QWidget>
#include <QScrollArea>
#include <QScrollBar>

class Scene;
class SceneManager;

/*!
	\defgroup animation Animation
 	\ingroup uiapi
*/

/*! Animation is a helper class for setting up UI animations.

    Animations can be created as standalone objects (for simpler single-item animations), and can also be used
    within the Scene Manager for transitions between scenes.

    By default, Animation upon being started will interpolate between 0.0 and 1.0.

    <b>Accessibility</b>
    General motion can be enabled/disabled via the binaryninja.ui.motion setting. Whenever motion is disabled,
    instead of interpolating between values, animations will only fire the start and end value.

    Your options regarding this are:
    - Check for Animation::reducedMotionEnabled() and program alternate transition logic if required.
    - Write transitions in such a way that an instant transition looks appropriate
    - Utilize the overridingReducedAnimationsForAVeryGoodReason() function.

    It is worth keeping in mind that this is an \e accessibility feature, and overriding reduced motion should only
        be done where it is \e explicitly appropriate. (e.g. Loading spinners and other simple critical animations.)

	\ingroup animation
*/
class BINARYNINJAUIAPI Animation : public QVariantAnimation
{
	Q_OBJECT

	std::string m_name;
	bool m_overrideReducedAnimations = false;
	QAbstractAnimation::Direction m_direction = QAbstractAnimation::Forward;
	bool m_ownerDestroyed = false;

	std::unordered_map<QObject*, std::vector<std::string>> m_properties;
	std::vector<std::function<void(double)>> m_callbacks;
	std::vector<std::function<void(QAbstractAnimation::Direction)>> m_startCallbacks;
	std::vector<std::function<void(QAbstractAnimation::Direction)>> m_endCallbacks;

	friend SceneManager;

	void addPropertyCallback(QObject* obj, QString property);
	void addCallback(std::function<void(double)> callback);

	void addStartCallback(std::function<void(QAbstractAnimation::Direction)> startCallback);
	void addEndCallback(std::function<void(QAbstractAnimation::Direction)> endCallback);
	Animation(QObject* owner = nullptr);
	Animation* invertDirection();

public:
	/*! Create a new animation object

	    A note on lifetimes: if a given \c Animation is passed to a \c SceneManager , the SceneManager will take
	   ownership of the \c Animation , and it will not be deleted until the \c SceneManager itself is.

	    \param owner
	    \return Pointer to the new \c Animation object
	*/
	static Animation* create(QObject* owner = nullptr);
	/*! Creates a copy of the target animation. This will duplicate all configurable values, callbacks, etc.

	     Lifetime note: The parent of the new animation will be set to the target's.

	    \param animation Animation to be copied.
	    \return Pointer to the new \c Animation object
	*/
	static Animation* createCopy(Animation* animation);
	/*! Whether reduced motion is enabled for the BinaryNinja Application.

	    This will return true if the `binaryninja.ui.motion` setting is enabled.

	    The `binaryninja.ui.motion` setting will be enabled automatically if the Operating System's reduce motion
	    setting is turned on.

	    \return Whether reduced motion is enabled.
	*/
	static bool reducedMotionEnabled() { return false; }
	/*! Set the name of the animation. This is only useful for debugging purposes, however if you are working
	    with several animations in a SceneManager, it's highly recommended you give it something, as error messages
	    regarding this animation will report it.

	    \param name Name of the animation.
	    \return Pointer to this \c Animation object
	*/
	Animation* named(std::string name)
	{
		m_name = name;
		return this;
	}
	/*! Set the duration of the animation; that is, "how long should it take to interpolate between 0.0 and 1.0?"

	    \param msecs Duration of the animation in msecs;
	    \return Pointer to this \c Animation object
	*/
	Animation* withDuration(int msecs)
	{
		setDuration(msecs);
		return this;
	};
	/*! Allows setting the QEasingCurve for this animation.

	    It's recommended you read the official Qt documentation here: https://doc.qt.io/qt-6/qeasingcurve.html

	    \param curve Easing curve
	    \return Pointer to this \c Animation object
	*/
	Animation* withEasingCurve(QEasingCurve curve)
	{
		setEasingCurve(curve);
		return this;
	}
	/*! Callback to fire at the start of the animation.

	    It will be passed an \c AnimationDirection value, which is relevant when using animations for linear scene
	    transitions.

	    \see SceneManager::SceneBuilder::onSetup

	    \note This will fire at the start even if the animation is running backwards, i.e. in a linear scene transition.

	    \param startCallback Function to be called
	    \return Pointer to this \c Animation object
	*/
	Animation* thenOnStart(std::function<void(QAbstractAnimation::Direction)> startCallback);
	/*! Callback to fire when this animation's progress is updated. This is where the bulk of your animation
	     logic will go.

	     Will be passed a \c double value between 0.0 and 1.0.

	    \param callback Callback to be fired
	    \return Pointer to this \c Animation object
	*/
	Animation* thenOnValueChanged(std::function<void(double)> callback);
	/*! By passing this an object and associated property name, a Q_PROPERTY of a given object can be updated with
	     the animation's state. It will be passed a \c double , containing a value between 0.0 and 1.0.

	     (This is functionally equivalent to thenOnValueChanged, with the primary difference being where you decide
	        to implement your animation logic.)

	     This can be particularly useful if you have an opacity property you want to fade in or out, or you prefer
	     to implement some animation related logic in a QProperty setter. It can also be useful for debugging via
	     the UI debugger.

	    An example usage of this involves manipulating the properties of \c ContentAlignmentAnimatingWidget to
	    	move a widget for your animation.

	    \param obj QObject target
	    \param property Q_PROPERTY target name
	    \return Pointer to this \c Animation object
	*/
	Animation* thenUpdatePropertyOnValueChanged(QObject* obj, QString property);
	/*! Callback to fire at the end of the animation.

	    It will be passed an \c AnimationDirection value, which is relevant when using animations for linear scene
	    transitions.

	    \see SceneManager::SceneBuilder::onTeardown

	    \note This will fire at the end even if the animation is running backwards, i.e. in a linear scene transition.

	    \param endCallback Function to be called
	    \return Pointer to this \c Animation object
	*/
	Animation* thenOnEnd(std::function<void(QAbstractAnimation::Direction)> endCallback);

	/// ONLY use this if you are doing something like a loading spinner. AVOID IT
	Animation* overridingReducedAnimationsForAVeryGoodReason()
	{
		m_overrideReducedAnimations = true;
		return this;
	};

	/*! Fire the animation.

	     These events will occur, in order:
	     -# Start callbacks will be fired.
	     -# The internal state will begin iterating through 0.0 to 1.0, or 1.0 to 0.0 if backwards. Callbacks passed by
	       thenOnValueChanged will fire now. If reduced motion is enabled, this will only fire the start and end value.
	     -# After reaching its destination value, End callbacks will be fired.
	*/
	void start();

signals:
	/*! Signal fired after the animation ends and all callbacks have fired.

	     \warning Do NOT use this. Do NOT expect this to work the way you intend. Your connection WILL be disconnected
	                unless you explicitly reconnect it every time the animation is about to fire. There are callbacks
	                that do what you want.
	*/
	void ended();

protected:
	bool event(QEvent* event) override;
	void updateCurrentValue(const QVariant& value) override;
	void updateState(QAbstractAnimation::State newState, QAbstractAnimation::State oldState) override;
};

/*! Provides simple static functions wrapping common transformations applied to Qt Widgets.

	\ingroup animation
*/
class BINARYNINJAUIAPI AnimationHelper
{
public:
	/*! Set the opacity of a given QLabel. Specifically, this will set the text opacity.

	    \param label Target label.
	    \param opacity Target opacity. Value between 0.0 and 1.0.
	*/
	static void SetLabelOpacity(QLabel* label, double opacity);
};

/*! This is an internal object used for tracking Scene information.

 	Create an instance of a scene via AnimationStateMachine->createScene();

	\ingroup animation
*/
class Scene : public QObject
{
	Q_OBJECT

	friend SceneManager;
	std::unordered_map<std::string, Animation*> m_stateTransitions;
	std::string id;

	Scene(QObject* parent) : QObject(parent) {};
	void setStateTransitionAnimation(Scene* scene, Animation* transition);
	void sendSetupSceneSignal(std::string previousScene);
	void sendTeardownSceneSignal(std::string nextScene);
signals:
	void setupScene(std::string transitioningFrom);
	void teardownScene(std::string transitionedTo);
};

/*! Helper widget that animates the alignment of a given child widget.

	\ingroup animation
*/
class BINARYNINJAUIAPI ContentAlignmentAnimatingWidget : public QWidget
{
	Q_OBJECT

	double m_transitionState = 0.0;
	Qt::Alignment m_stopOneAlignment = Qt::AlignLeft | Qt::AlignVCenter;
	Qt::Alignment m_stopTwoAlignment = Qt::AlignRight | Qt::AlignVCenter;
	QWidget* m_widget;
	QMargins m_padding;

	QPoint getWidgetPositionForAlignment(Qt::Alignment align);

public:
	ContentAlignmentAnimatingWidget(QWidget* parent = nullptr);

	Q_PROPERTY(Qt::Alignment stopOneAlignment READ stopOneAlignment WRITE setStopOneAlignment)
	Qt::Alignment stopOneAlignment() const { return m_stopOneAlignment; }
	void setStopOneAlignment(Qt::Alignment align)
	{
		m_stopOneAlignment = align;
		updateWithTransitionState(m_transitionState);
	}

	Q_PROPERTY(Qt::Alignment stopTwoAlignment READ stopTwoAlignment WRITE setStopTwoAlignment)
	Qt::Alignment stopTwoAlignment() const { return m_stopTwoAlignment; }
	void setStopTwoAlignment(Qt::Alignment align)
	{
		m_stopTwoAlignment = align;
		updateWithTransitionState(m_transitionState);
	}

	Q_PROPERTY(QMargins padding READ padding WRITE setPadding);
	QMargins padding() const { return m_padding; }
	void setPadding(QMargins padding)
	{
		m_padding = padding;
		updateWithTransitionState(m_transitionState);
	}

	Q_PROPERTY(QWidget* widget READ widget WRITE setWidget)
	QWidget* widget() const { return m_widget; }
	void setWidget(QWidget* widget);

protected:
	void resizeEvent(QResizeEvent* event) override
	{
		QWidget::resizeEvent(event);
		updateWithTransitionState(m_transitionState);
	};

public slots:
	void updateWithTransitionState(double transitionState);
};
/*! Moving between different UI states can be very tedious and end up producing incredibly complex and
        often indecipherable code. Adding animations into the mix does not help.

    The SceneManager class, along with the rest of the utilities provided for Animation, aim to help with writing
    more maintainable and parseable code for UI state transitions.

    This documentation block goes over the general concepts of this class, while the implementation details are
    documented on the functions themselves.

   	\note While this manager has several features to make things nicer, you should always have a clear idea of which state
    you are in, which state you want to get to, how those two are connected, and the exact behavior that will result
    from firing a given scene transition.

    \note Multi-scene UI can \em easily become very complex, and while this class can help organize and facilitate that,
        care should always be taken to ensure it is being used properly and clearly.

    \note Tools such as https://asciiflow.com/ and other drawing utilities are often useful to create a clearer overview
        of the "State Machine" that you are building.

    \note When the SceneManager encounters errors related to transitions, programmer error is presumed, and the
        application will halt and output debug information via stderr.

    <b>A general note on multi-stage animations in Binary Ninja:</b>

    These should ideally \b not be used in locations in the application where interactions should feel instant.
    Login screens, the new tab page, update UI, etc. are valid applications for this; however,
    animations within your analysis plugin providing UI may feel clunky and out of place.

    This manager \em can, however, be used for managing multiple scenes regardless, with the Animations' simply
    lacking a valueUpdated callback and duration set to 0ms, relying on setup and teardown callbacks instead.

    <h2>Linear connections</h2>

    Linear connections are useful for setting up multi-stage UIs. They can "pathfind" between connected scenes,
    move in both directions, and be swapped via \c transitionToScene .

    connectScenesLinear will create a bidirectional link between two Scenes, firing the animation in reverse if
    a backwards transition is requested. See the \c Animation class documentation for more info on reversed animations.

    <pre>
        ┌─────────────┐           ┌─────────────┐           ┌─────────────┐
        │             ├──────────►│             ├──────────►│             │
        │   Scene 1   │ Animat. 1 │   Scene 2   │ Animat. 2 │   Scene 3   │
        │             │◄──────────┤             │◄──────────┤             │
        └─────────────┘           └─────────────┘           └─────────────┘
	</pre>

    In the above described chain, if one were currently in Scene 1, \c transitionToScene("scene3") could be called,
    which would walk the chain of required scenes to transition to Scene 3. In this case, Animation 1 would be fired,
    and then immediately after it finished, Animation 2 would be fired, ending in Scene 3.

    \note It is worth noting that, in the case of Scene 1 having a "Direct Connection" to Scene 3, that the direct
            connection would be prioritized. The <b>Direct Connections</b> section goes over this in more detail.

    One could also call \c mySceneManager->transitionToScene(mySceneManager->nextScene()) , which would transition
    from Scene 1 to Scene 2.

    <h3> Linear connection loops </h3>

    These aren't recommended, as they can cause minor confusion related to linear pathfinding

    See \c SceneManager::transitionToScene .

    Linear connections can loop back around. This can be useful for setting up simple on-off transitions, carousels,
    etc. However, in almost all cases, it can be more clear to utilize direct connections for loopbacks, to more
   explicitly define the behavior required, and to avoid confusion regarding the linear pathfinding.

	<pre>
                   ┌─────────────┐           ┌─────────────┐           ┌─────────────┐
        ──────────►│             ├──────────►│             ├──────────►│             ├───────────
         Animat. 3 │   Scene 1   │ Animat. 1 │   Scene 2   │ Animat. 2 │   Scene 3   │ Animat. 3
        ───────────┤             │◄──────────┤             │◄──────────┤             │◄──────────
                   └─────────────┘           └─────────────┘           └─────────────┘
	</pre>

    <h2>Direct connections</h2>

    Direct connections are the alternative to linear ones. They allow building out much more complex graphs,
        more explicit handling of loopbacks, etc, at the cost of not being able to "pathfind" to other animations.

    Instead, a scene with only direct connections MUST transition to one it is directly connected to.

    Direct connections will also override Linear ones. When doing pathfinding, the Scene Manager will look for any
    direct links between the current and target scenes before checking for ones Linearly connected.

    For more information on pathfinding, see \c SceneManager::transitionToScene

    <h2>Scene setup/teardown</h2>

    Scenes also have setup and teardown callbacks. See also \c SceneBuilder .

    These differ from Animation start and end callbacks in that, a Scene can have multiple animations between
    different scenes, but may have some shared code that always needs to be ran when transitioning to/away from
    this scene.

    <b>Overview</b>
    The following is an exhaustive list of what will happen when transitioning between two example scenes,
        \c "scene1" and \c "scene2"

    -# A suitable path is found between the two. In this case we assume they are connected linearly to one another.
    -# \c "scene2" 's \c onSetup callback will be fired.
    -# Animation begins.
    -# Animation onStart callbacks fired.
    -# Animation value interpolation loop. onValueChanged callbacks fired.
    -# Animation onEnd callbacks fired.
    -# \c "scene1" 's \c onTeardown callbacks are fired.

    To transition back, we call, \c transitionToScene("scene1").

    -# We find the bidirectional path back to the first animation.
    -# \c "scene1" 's \c onSetup callback is fired.
    -# Animation begins.
    -# Animation onStart callbacks fired, this time with the direction argument set to \c AnimationDirection::Backwards
    -# Animation value interpolation loop runs backwards, going from 1.0 to 0.0
    -# Animation onEnd callbacks fired, this time with the direction argument set to \c AnimationDirection::Backwards
    -# \c "scene2" 's \c onTeardown callbacks are fired.

    \ingroup animation
*/
class BINARYNINJAUIAPI SceneManager : public QObject
{
	Q_OBJECT

	std::string m_currentSceneID = "";
	std::unordered_map<std::string, std::pair<std::string, std::string>> m_sceneDirectionLinks;
	std::unordered_map<std::string, Scene*> m_scenes;

	std::unordered_map<QObject*, QMetaObject::Connection> m_activeTransitionConnections;

	bool m_transitionRunning;
	std::deque<std::string> m_queue;
	void processQueue();

public:
	/*! The SceneBuilder class is a helper for the buildup/teardown process of a Scene.

	    \warning DO NOT create an instance of this class directly! You will be given an instance of it via \c
	   SceneManger::createScene!

	    This is primarily useful for putting up UI prep code, via callbacks to be fired before the Animation is hit.
	    It also allows separating code that should be preserved even if the animations and links between scenes are
	   modified.

	    As an example, in a multi-scene dialog, one would "place" the objects for the next scene in a
	        setup callback, and would remove or hide them in a teardown callback.

	    \c onSetup will be passed the name of the scene being transitioned away from.

	    \c onTeardown will be passed the name of the scene that was transitioned to.

	    <b>Example</b>

	    An example Scene setup pattern might look like this.

	    \code{.cpp}

	    auto selecting = m_sceneManager->createScene("selecting");
	    // Called BEFORE the transition to this scene starts.
	    selecting.onSetup([this](std::string) {
	        m_someLabel->setVisible(true);
	        m_actionButton->setText("Update");
	        m_cancelButton->setText("Cancel");
	        // We want to reconnect our buttons to different signals, now.
	        m_actionButton->disconnect();
	        m_cancelButton->disconnect();
	        connect(m_actionButton, &QPushButton::clicked, this, &MyDialog::ADifferentCallback);
	        // Maybe in the past this sent us back a scene, but now we want it to close the dialog entirely.
	        connect(m_cancelButton, &QPushButton::clicked, this, &QWidget::close);
	    });
	    // Called AFTER the animation transitioning away from this scene has ended.
	    selecting.onTeardown([this](std::string) {
	        m_someLabel->setVisible(false);
	        m_actionButton->disconnect();
	        m_cancelButton->disconnect();
	    });
	    \endcode

	    onSetup and onTeardown also return references to the given SceneBuilder, \em so, if it were preferred,
	    one could instead use the following pattern.

	    \code{.cpp}
	    m_sceneManager->createScene("modifying")
	        .onSetup([this](std::string){
	            m_someLabel->setVisible(true);
	        })
	        .onTeardown([this](std::string){
	            m_someLabel->setVisible(false);
	        });
	    \endcode

		\ingroup animation
	*/
	class SceneBuilder
	{
		friend SceneManager;
		SceneManager* m_mgr;
		std::string m_id;

	public:
		SceneBuilder(SceneManager* mgr, const std::string& name);
		SceneBuilder& onSetup(std::function<void(std::string fromScene)> func);
		SceneBuilder& onTeardown(std::function<void(std::string toScene)> func);
	};
	~SceneManager();

	/*! Create a new Scene Manager

	    \note Object lifetime: If an owner is not passed, YOU are responsible for deleting this.

	    \param owner Parent QObject. When the parent is deallocated, this SceneManager will be as well.
	*/
	SceneManager(QObject* owner = nullptr);
	/*! Create a scene with a given name.

	    This name will be used as the scene's "identifier", and is what should be passed to all functions of
	    this class that request a scene name.

	    \param name Name of the Scene
	    \return a SceneBuilder object, for you to add setup/teardown callbacks to.
	*/
	SceneBuilder createScene(const std::string& name);

	/*! Set the initial scene and perform the required setup to load it.

	    \warning This MUST be called for the SceneManager to operate and perform transitions.

	    \c onSetup will be called for the target scene, with the argument \c ""

	    \param initial target scene
	*/
	void setupInitialScene(const std::string& initial);

	/*! Create a connection between \c firstScene and \c secondScene with a given animation.

	    This will create a direct link, instead of a linear one. If there's a linear path between these two scenes,
	    this connection will overrule that and use the provided animation to transition directly instead.

	    This can also be used for transitions that do not need to be bidirectional.

	    \param firstScene Initial scene
	    \param secondScene Target scene
	    \param animation Animation to be used when transitioning from firstScene to secondScene.
	*/
	void connectScenes(const std::string& firstScene, const std::string& secondScene, Animation* animation);
	/*! Creates a linear connection between two scenes with a given animation

	    In terms of direction, the two scenes will be treated (and connected) as follows:

		<pre>
	                          ◄─── Previous
	                        ┌────────────────────┐
	        ┌───────────────▼───┐             ┌──┴────────────────┐
	        │                   │             │                   │
	        │ "firstScene"      │ "animation" │ "secondScene"     │
	        │                   │             │                   │
	        └───────────────┬───┘             └──▲────────────────┘
	                        └────────────────────┘
	                                 Next ──►
		</pre>

	    By connecting a third scene with "secondScene" here as the first scene, you can create a chain.

	    \param firstScene First scene to connect
	    \param secondScene Second scene to connect
	    \param animation Animation linking the two scenes together, which will be used whenever transitioning between
	                        the two.
	*/
	void connectScenesLinear(const std::string& firstScene, const std::string& secondScene, Animation* animation);

	/*! Get the currently active scene

	    \return The name of the currently active scene.
	*/
	const std::string currentScene();

	/*! Transition to a given scene.

	    This will look for, in this order:
	    -# A direct link between the current Scene and provided \c targetScene
	    -# Whether the target scene is directly before or after this scene
	    -# Whether the target scene can be located by walking the scene chain forwards
	    -# Whether the target scene can be located by walking the scene chain in reverse.

	    It will then kick off the transition to that scene, if it was found. If it was not, serious programmer error
	        is presumed and the application will halt and output debug information via stderr.

	    \param targetScene Scene to transition to.
	*/
	void transitionToScene(const std::string targetScene);

	/*! Returns the name of the current scene's "Previous Scene", if this scene is part of a linear chain.

	    If this scene was never passed to \c connectScenesLinear as the second scene, this will be empty.

	    \return Name of previous scene, empty if current is not linearly connected.
	*/
	std::string prevScene();

	/*! Returns the name of the current scene's "Next Scene", if this scene is part of a linear chain.

	    If this scene was never passed to \c connectScenesLinear as the first scene, this will be empty.

	    \return Name of next scene, empty if current is not linearly connected.
	*/
	std::string nextScene();

	/*! Check whether a transition is currently running.

	    \return Whether a transition is currently running.
	*/
	bool transitionRunning() const { return m_transitionRunning; }

private:
	std::unordered_map<std::string, std::weak_ptr<SceneBuilder>> m_sceneBuilders;
};
