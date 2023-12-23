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

enum AnimationDirection {
	Forwards,
	Backwards
};
/*! Animation is a helper class for setting up UI animations.

	Animations can be created as standalone objects (for simpler single-item animations), and can also be used
	within the SceneManager for transitions between scenes.

	By default, Animation upon being started will interpolate between 0.0 and 1.0.

	<b>Accessibility</b>
	General motion can be enabled/disabled via the binaryninja.ui.motion setting. Whenever motion is disabled,
	instead of interpolating between values, animations will only fire the start and end value.

	Your options regarding this are:
	* Check for Animation::reducedMotionEnabled() and program alternate transition logic if required.
	* Write transitions in such a way that an instant transition looks appropriate
	* Utilize the overridingReducedAnimationsForAVeryGoodReason() function.

	It is worth keeping in mind that this is an \e accessibility feature, and overriding reduced motion should only
		be done where it is \e explicitly appropriate. (e.g. Loading spinners and other simple critical animations.)

 */
class BINARYNINJAUIAPI Animation : public QVariantAnimation
	{
		Q_OBJECT

		std::string m_name;
		bool m_overrideReducedAnimations = false;
		AnimationDirection m_direction = Forwards;
		bool m_ownerDestroyed = false;

		std::unordered_map<QObject*, std::vector<std::string>> m_properties;
		std::vector<std::function<void(double)>> m_callbacks;
		std::vector<std::function<void(AnimationDirection)>> m_startCallbacks;
		std::vector<std::function<void(AnimationDirection)>> m_endCallbacks;

		friend SceneManager;

		void addPropertyCallback(QObject* obj, QString property);
		void addCallback(std::function<void(double)> callback);

		void addStartCallback(std::function<void(AnimationDirection)> startCallback);
		void addEndCallback(std::function<void(AnimationDirection)> endCallback);
		Animation(QObject* owner = nullptr);
		Animation* invertDirection();

	public:
		static Animation* create(QObject* owner = nullptr);
		static Animation* createCopy(Animation* animation);
		static bool reducedMotionEnabled() { return false; }
		Animation* named(std::string name) { m_name = name; return this; }
		Animation* withDuration(int msecs) { setDuration(msecs); return this; };
		Animation* withEasingCurve(QEasingCurve curve) { setEasingCurve(curve); return this; }
		Animation* thenOnStart(std::function<void(AnimationDirection)> startCallback);
		Animation* thenOnValueChanged(std::function<void(double)> callback);
		Animation* thenUpdatePropertyOnValueChanged(QObject* obj, QString property);
		Animation* thenOnEnd(std::function<void(AnimationDirection)> endCallback);
		/// ONLY use this if you are doing something like a loading spinner. AVOID IT
		Animation* overridingReducedAnimationsForAVeryGoodReason() { m_overrideReducedAnimations = true; return this; };

		void start();

	signals:
		void ended();

	protected:
		bool event(QEvent *event) override;
		void updateCurrentValue(const QVariant &value) override;
		void updateState(QAbstractAnimation::State newState, QAbstractAnimation::State oldState) override;
	};

	/*! Provides simple static functions wrapping common transformations applied to Qt Widgets.
	 */
	class BINARYNINJAUIAPI AnimationHelper
	{
	public:
		static void SetLabelOpacity(QLabel* label, double opacity);
	};

	/*! Create an instance via AnimationStateMachine->createScene();
	*/
	class Scene : public QObject
	{
		Q_OBJECT

		friend SceneManager;
		std::unordered_map<std::string, Animation*> m_stateTransitions;
		std::string id;

		Scene(QObject* parent) : QObject(parent) {};
		void setStateTransitionAnimation(Scene* state, Animation* transition);
		void sendSetupSceneSignal(std::string previousScene);
		void sendTeardownSceneSignal(std::string nextScene);
	signals:
		void setupScene(std::string transitioningFrom);
		void teardownScene(std::string transitionedTo);
	};
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
		void setStopOneAlignment(Qt::Alignment align) { m_stopOneAlignment = align; updateWithTransitionState(m_transitionState); }

		Q_PROPERTY(Qt::Alignment stopTwoAlignment READ stopTwoAlignment WRITE setStopTwoAlignment)
		Qt::Alignment stopTwoAlignment() const { return m_stopTwoAlignment; }
		void setStopTwoAlignment(Qt::Alignment align) { m_stopTwoAlignment = align; updateWithTransitionState(m_transitionState); }

		Q_PROPERTY(QMargins padding READ padding WRITE setPadding);
		QMargins padding() const { return m_padding; }
		void setPadding(QMargins padding) { m_padding = padding; updateWithTransitionState(m_transitionState); }

		Q_PROPERTY(QWidget* widget READ widget WRITE setWidget)
		QWidget* widget() const { return m_widget; }
		void setWidget(QWidget* widget);
	protected:
		void resizeEvent(QResizeEvent *event) override { QWidget::resizeEvent(event); updateWithTransitionState(m_transitionState);  };

	public slots:
		void updateWithTransitionState(double transitionState) ;
	};
	/*! Moving between different UI states can be very tedious and end up producing incredibly complex and
			often indecipherable code. Adding animations into the mix does not help.

		The SceneManager class, along with the rest of the utilities provided for Animation, aim to help with writing
	 	more maintainable and parseable code for UI state transitions.

	 	TODO v detailed docs + usgae once this is known to be fully filled out.
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
		class SceneBuilder {
			friend SceneManager;
			SceneManager* m_mgr;
			std::string m_id;
		public:
			SceneBuilder(SceneManager* mgr, const std::string& name);
			SceneBuilder& onSetup(std::function<void(std::string fromScene)> func);
			SceneBuilder& onTeardown(std::function<void(std::string toScene)> func);
		};
		~SceneManager();
		SceneManager(QObject* owner = nullptr);
		SceneBuilder createScene(const std::string& name);
		void setupInitialScene(const std::string& initial);

		void connectScenes(const std::string& firstScene, const std::string& secondScene, Animation* animation);
		void connectScenesLinear(const std::string& firstScene, const std::string& secondScene, Animation* animation);

		const std::string currentScene();
		void transitionToScene(const std::string scene);
		std::string prevScene();
		std::string nextScene();

		bool transitionRunning() const { return m_transitionRunning; }
	private:
		std::unordered_map<std::string, std::weak_ptr<SceneBuilder>> m_sceneBuilders;
	};
